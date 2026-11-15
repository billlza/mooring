// SPDX-License-Identifier: GPL-3.0-or-later

//! `sim accept-network` (design §10.2), layer by layer. The daemon's
//! record takes the network the M7 reports only at a word that names it,
//! while the record and the daemon's latest poll both say that the M7
//! reports it, and only when whoever asked hears the answer. A connection
//! hands the request to the loop and waits a bounded while for its
//! answer, and the loop holds a bounded number of requests. The loop
//! answers after a tick and changes no file but the
//! record's. The command shows both networks, asks, and reports each
//! refusal in a sentence. The M7 is the loopback stub, and the daemon the
//! command talks to is a stand-in on a Unix socket.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use mooring_daemon_core::MacStatusV2;
use mooring_daemon_core::console::{ConsoleStatus, UndeployedStatus};
use mooring_daemon_core::control::{
    DaemonReply, DaemonRequest, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES, ProtocolLine,
    Refusal, decode_reply, encode_line,
};
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_daemon_core::sim_network::{BaselineOrigin, NotAccepted, SimNetwork, SimNetworkStatus};
use mooring_model::ExitSite;
use mooring_store::{SIM_NETWORK_FILE, read_sim_network};

use super::daemon::{Running, harness};
use super::deployed::shared;
use super::sim_network::{
    SWAPPED, at, baseline_of, cmlink, cmlink_document, harness_with_the_stub_m7, network, on_disk,
    reported, run_against, run_polling_every, shown_by, swapped_since, track, unnamed,
    unnamed_document,
};
use super::support::{Harness, NOW};
use super::user::fixture;
use crate::daemon::deployed::{self, Stopped};
use crate::daemon::serve::{End, Limits, MAX_CLIENTS, serve};
use crate::daemon::sim_network::{NetworkWatch, WRITE_RETRY};
use crate::daemon::{AcceptRequest, Asked, Control, RunPaths};
use crate::error::{EXIT_LOCAL, refusal_text};
use crate::prompt::Answer;

/// How long a test waits for a reply or a connection's end.
const DEADLINE: Duration = Duration::from_secs(10);

/// The log's line for the SIM without a name taken in place of the
/// fixture's SIM.
const ACCEPTED: &str = "sim network: a SIM without a name (234-20) is taken as the one on record at the operator's word (`sim accept-network`), in place of CMLink (234-30); the carrier check and the billing cycle stay as they are";

/// Each reason a network is not taken, with the daemon's refusal for it
/// and the sentence both are reported in.
const REASONS: [(NotAccepted, Refusal, &str); 3] = [
    (
        NotAccepted::NoOtherNetwork,
        Refusal::NoOtherSimNetwork,
        "there is no network other than the one on record",
    ),
    (
        NotAccepted::NotAttached,
        Refusal::M7NotAttached,
        "the latest poll of the M7 did not find it attached",
    ),
    (
        NotAccepted::ReportChanged,
        Refusal::SimNetworkReportChanged,
        "the M7 no longer reports the network that was to be taken",
    ),
];

/// A third network, neither the fixture's nor the SIM without a name's.
fn third() -> SimNetwork {
    network(Some("Other"), "234", "15")
}

/// A poll that did not reach the M7.
fn unreachable() -> RouterReading {
    RouterReading::Unavailable {
        reason: RouterUnavailableReason::Unreachable,
        last_polled_at: None,
    }
}

// --- The record ---------------------------------------------------------

/// A watch in `run` whose record holds the fixture's SIM, first seen at
/// [`NOW`], with the SIM without a name reported since 600 s after it.
fn swapped_watch(run: &Path, exit: &ExitSite) -> NetworkWatch {
    let (mut watch, _) = NetworkWatch::open(run, exit);
    track(&mut watch, exit, Some(&reported(&cmlink(), 0)));
    track(&mut watch, exit, Some(&reported(&unnamed(), 600)));
    assert_eq!(watch.status(), swapped_since(600));
    watch
}

/// The word, 700 s after [`NOW`], that `shown` is the network on record,
/// with `latest` the daemon's latest poll and an asker who hears the
/// answer or, with `told` false, has gone: what the watch says and the
/// answer it handed over.
fn accept(
    watch: &mut NetworkWatch,
    shown: &SimNetwork,
    latest: &RouterReading,
    told: bool,
) -> (Vec<String>, Result<(), NotAccepted>) {
    let mut handed = None;
    let notes = watch.accept(shown, latest, at(700), Instant::now(), |answer| {
        handed = Some(answer);
        told
    });
    (notes, handed.unwrap())
}

/// The network the M7 reports is taken at a word that names it: it is the
/// baseline from the time of the word, the record says that it was
/// accepted, the log says which network replaced which, and the file
/// holds it. A restart keeps it, and the SIM that was on record before is
/// another network from then on.
#[test]
fn the_network_the_m7_reports_is_taken_at_a_word_that_names_it() {
    let run = tempfile::tempdir().unwrap();
    let exit = fixture(|_| {});
    let mut watch = swapped_watch(run.path(), exit.exit());
    let (notes, handed) = accept(&mut watch, &unnamed(), &reported(&unnamed(), 660), true);
    assert_eq!(notes, [ACCEPTED]);
    assert_eq!(handed, Ok(()));
    let accepted = baseline_of(BaselineOrigin::Accepted, unnamed(), 700);
    assert_eq!(watch.status(), accepted);
    assert_eq!(on_disk(run.path()).status(), &accepted);
    drop(watch);

    let (mut watch, note) = NetworkWatch::open(run.path(), exit.exit());
    assert_eq!(note, None);
    assert_eq!(watch.status(), accepted);
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 720))),
        Vec::<String>::new()
    );
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 780))),
        [
            "sim network: the M7 reports CMLink (234-30), where it reported a SIM without a name (234-20) under the recorded carrier check and billing cycle; if the SIM was changed, record both again (swap-day.md, section 2, steps 3 to 6)"
        ]
    );
}

/// A word that the record or the daemon's latest poll does not bear out
/// takes nothing: the asker is handed the reason, nothing is said, and
/// neither the record nor its file changes.
#[test]
fn a_word_the_record_or_the_latest_poll_does_not_bear_out_takes_nothing() {
    let exit = fixture(|_| {});
    // The M7 reports another network than the one on record.
    for (shown, latest, reason) in [
        (unnamed(), unreachable(), NotAccepted::NotAttached),
        // The M7 reports the one on record again.
        (
            unnamed(),
            reported(&cmlink(), 660),
            NotAccepted::ReportChanged,
        ),
        // The word names the network on record, or one the M7 never
        // reported.
        (
            cmlink(),
            reported(&unnamed(), 660),
            NotAccepted::ReportChanged,
        ),
        (
            third(),
            reported(&unnamed(), 660),
            NotAccepted::ReportChanged,
        ),
        // The M7 reports a third network by now.
        (
            unnamed(),
            reported(&third(), 660),
            NotAccepted::ReportChanged,
        ),
    ] {
        let run = tempfile::tempdir().unwrap();
        let mut watch = swapped_watch(run.path(), exit.exit());
        let file = fs::read(run.path().join(SIM_NETWORK_FILE)).unwrap();
        let (notes, handed) = accept(&mut watch, &shown, &latest, true);
        assert_eq!(handed, Err(reason), "{shown:?} {latest:?}");
        assert_eq!(notes, Vec::<String>::new());
        assert_eq!(watch.status(), swapped_since(600));
        assert_eq!(fs::read(run.path().join(SIM_NETWORK_FILE)).unwrap(), file);
    }
    // The record holds no other network: the M7 reports the one on
    // record, or the latest poll has not been set against the record yet.
    for (shown, latest) in [
        (cmlink(), reported(&cmlink(), 60)),
        (unnamed(), reported(&unnamed(), 60)),
    ] {
        let run = tempfile::tempdir().unwrap();
        let (mut watch, _) = NetworkWatch::open(run.path(), exit.exit());
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 0)));
        let (notes, handed) = accept(&mut watch, &shown, &latest, true);
        assert_eq!(handed, Err(NotAccepted::NoOtherNetwork), "{shown:?}");
        assert_eq!(notes, Vec::<String>::new());
        assert_eq!(
            watch.status(),
            baseline_of(BaselineOrigin::NoRecord, cmlink(), 0)
        );
    }
    // The record has no baseline yet.
    let run = tempfile::tempdir().unwrap();
    let (mut watch, _) = NetworkWatch::open(run.path(), exit.exit());
    let (notes, handed) = accept(&mut watch, &cmlink(), &reported(&cmlink(), 0), true);
    assert_eq!(handed, Err(NotAccepted::NoOtherNetwork));
    assert_eq!(notes, Vec::<String>::new());
    assert_eq!(watch.status().baseline, None);
    assert_eq!(read_sim_network(run.path(), 64).unwrap(), None);
}

/// A network that would be taken is not when whoever asked has gone:
/// no one was told, so nothing changes and nothing is said.
#[test]
fn nothing_is_taken_when_whoever_asked_has_gone() {
    let run = tempfile::tempdir().unwrap();
    let exit = fixture(|_| {});
    let mut watch = swapped_watch(run.path(), exit.exit());
    let file = fs::read(run.path().join(SIM_NETWORK_FILE)).unwrap();
    let (notes, handed) = accept(&mut watch, &unnamed(), &reported(&unnamed(), 660), false);
    assert_eq!(handed, Ok(()));
    assert_eq!(notes, Vec::<String>::new());
    assert_eq!(watch.status(), swapped_since(600));
    assert_eq!(fs::read(run.path().join(SIM_NETWORK_FILE)).unwrap(), file);
}

/// A network taken is written as a tracked change is: a write that fails
/// is said with the change, the status carries the record meanwhile, and
/// the write is tried again when it is due.
#[test]
fn a_network_taken_that_cannot_be_written_is_said_and_written_when_due() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("run");
    let exit = fixture(|_| {});
    let (mut watch, _) = NetworkWatch::open(&missing, exit.exit());
    let begun = Instant::now();
    watch.track(exit.exit(), Some(&reported(&cmlink(), 0)), begun);
    watch.track(exit.exit(), Some(&reported(&unnamed(), 600)), begun);
    let mut handed = None;
    let notes = watch.accept(
        &unnamed(),
        &reported(&unnamed(), 660),
        at(700),
        begun,
        |answer| {
            handed = Some(answer);
            true
        },
    );
    assert_eq!(handed, Some(Ok(())));
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert_eq!(notes[0], ACCEPTED);
    assert!(
        notes[1].starts_with("sim network: the record could not be written ("),
        "{notes:?}"
    );
    let accepted = baseline_of(BaselineOrigin::Accepted, unnamed(), 700);
    assert_eq!(watch.status(), accepted);
    fs::create_dir(&missing).unwrap();
    assert_eq!(
        watch.track(
            exit.exit(),
            None,
            begun + WRITE_RETRY - Duration::from_secs(1)
        ),
        Vec::<String>::new()
    );
    assert_eq!(read_sim_network(&missing, 64).unwrap(), None);
    assert_eq!(
        watch.track(exit.exit(), None, begun + WRITE_RETRY),
        Vec::<String>::new()
    );
    assert_eq!(on_disk(&missing).status(), &accepted);
}

// --- The connection -----------------------------------------------------

/// A connection's limits. The loop's answer is waited for a minute, far
/// longer than a test takes to give one, so that no outcome hangs on how
/// soon the test's own thread runs.
const PATIENT: Limits = Limits {
    request: Duration::from_secs(2),
    write: Duration::from_secs(2),
    idle_check: Duration::from_millis(100),
    answer: Duration::from_secs(60),
};

/// The same with 50 ms for the loop's answer, for a loop that gives none.
const BRIEF: Limits = Limits {
    answer: Duration::from_millis(50),
    ..PATIENT
};

/// What a deployed daemon's connections and its loop share, and the
/// loop's ends of it.
fn deployed_control() -> (Arc<Control>, Asked) {
    let (control, asked) = Control::new();
    control.deployed.store(true, Ordering::SeqCst);
    (Arc::new(control), asked)
}

/// Serves one connection whose client has sent the request to take
/// `network`, under [`PATIENT`].
fn asked_to_take(
    control: &Arc<Control>,
    network: &SimNetwork,
) -> (BufReader<UnixStream>, Running<End>) {
    asked_to_take_under(control, network, PATIENT)
}

/// Serves one connection under `limits` whose client has sent the request
/// to take `network`: the client's reader, past the protocol line, and
/// how the connection ended. The client's time limit is set before the
/// connection is served: setsockopt(2) fails on macOS once the peer has
/// closed.
fn asked_to_take_under(
    control: &Arc<Control>,
    network: &SimNetwork,
    limits: Limits,
) -> (BufReader<UnixStream>, Running<End>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(DEADLINE)).unwrap();
    let request = DaemonRequest::AcceptSimNetwork {
        network: network.clone(),
    };
    client
        .write_all(&encode_line(&request, MAX_REQUEST_LINE_BYTES).unwrap())
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

/// The next reply on `reader`.
fn reply(reader: &mut BufReader<UnixStream>) -> DaemonReply {
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).unwrap();
    decode_reply(&line).unwrap()
}

/// Without a deployment the request is refused, and the loop hears
/// nothing of it.
#[test]
fn a_network_to_take_is_refused_without_a_deployment() {
    let (control, asked) = Control::new();
    let (mut reader, served) = asked_to_take(&Arc::new(control), &unnamed());
    assert_eq!(
        reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::NotDeployed
        }
    );
    assert_eq!(served.result(), End::Refused(Refusal::NotDeployed));
    assert!(asked.acceptances.try_recv().is_err());
}

/// The request reaches the loop with the network it names, and the loop's
/// answer goes back to the client: that the network was taken, or the
/// refusal that stands for the loop's reason.
#[test]
fn the_loops_answer_to_a_network_to_take_goes_back_to_the_client() {
    let (control, asked) = deployed_control();
    let (mut reader, served) = asked_to_take(&control, &unnamed());
    let request = asked.acceptances.recv_timeout(DEADLINE).unwrap();
    assert_eq!(request.network, unnamed());
    assert!(request.answer.send(Ok(())).is_ok());
    assert_eq!(reply(&mut reader), DaemonReply::SimNetworkAccepted);
    assert_eq!(served.result(), End::Answered);

    for (reason, refusal, _) in REASONS {
        let (mut reader, served) = asked_to_take(&control, &third());
        let request = asked.acceptances.recv_timeout(DEADLINE).unwrap();
        assert_eq!(request.network, third());
        assert!(request.answer.send(Err(reason)).is_ok());
        assert_eq!(
            reply(&mut reader),
            DaemonReply::Refused { reason: refusal },
            "{reason:?}"
        );
        assert_eq!(served.result(), End::Refused(refusal));
    }
}

/// A loop that does not come to the request within the answer's limit is
/// reported as busy, and when it comes to it then, it finds no one to
/// hand its answer to: it takes nothing for a client that was told
/// nothing was changed.
#[test]
fn a_loop_that_is_late_is_reported_busy_and_then_finds_no_one_waiting() {
    let (control, asked) = deployed_control();
    let (mut reader, served) = asked_to_take_under(&control, &unnamed(), BRIEF);
    let request = asked.acceptances.recv_timeout(DEADLINE).unwrap();
    assert_eq!(
        reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::LoopBusy
        }
    );
    assert_eq!(served.result(), End::Refused(Refusal::LoopBusy));
    assert!(request.answer.send(Ok(())).is_err());
}

/// A loop that takes no request holds as many as the connections that
/// can wait at once, and no more. Each asker is told that the loop is busy
/// when its wait ends, and leaves its request behind; the one that finds
/// as many waiting is told so without waiting and adds none. When the loop
/// comes to them, none has anyone waiting.
#[test]
fn a_loop_that_takes_no_request_holds_a_bounded_number_of_them() {
    assert_eq!(MAX_CLIENTS, 8);
    let (control, asked) = deployed_control();
    let busy = DaemonReply::Refused {
        reason: Refusal::LoopBusy,
    };
    for _ in 0..MAX_CLIENTS {
        let (mut reader, served) = asked_to_take_under(&control, &unnamed(), BRIEF);
        assert_eq!(reply(&mut reader), busy);
        assert_eq!(served.result(), End::Refused(Refusal::LoopBusy));
    }
    // The next would wait a minute for the loop, and is answered before
    // the test's own ten seconds are over.
    let (mut reader, served) = asked_to_take(&control, &third());
    assert_eq!(reply(&mut reader), busy);
    assert_eq!(served.result(), End::Refused(Refusal::LoopBusy));

    let waiting: Vec<AcceptRequest> = asked.acceptances.try_iter().collect();
    assert_eq!(waiting.len(), MAX_CLIENTS);
    for request in waiting {
        assert_eq!(request.network, unnamed());
        assert!(request.answer.send(Ok(())).is_err());
    }
}

/// A loop that has ended, before the request or with it in hand, ends
/// the connection without a reply.
#[test]
fn a_loop_that_has_ended_ends_the_connection_without_a_reply() {
    let (control, asked) = deployed_control();
    drop(asked);
    let (mut reader, served) = asked_to_take(&control, &unnamed());
    assert_eq!(served.result(), End::Stopping);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"");

    let (control, asked) = deployed_control();
    let (mut reader, served) = asked_to_take(&control, &unnamed());
    drop(asked.acceptances.recv_timeout(DEADLINE).unwrap());
    assert_eq!(served.result(), End::Stopping);
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"");
}

// --- The loop -----------------------------------------------------------

/// Every regular file under `dir`, by its path from it, with its bytes.
fn files_under(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let path = entry.path();
                let bytes = fs::read(&path).unwrap();
                files.insert(path.strip_prefix(dir).unwrap().to_path_buf(), bytes);
            }
        }
    }
    files
}

/// The paths whose bytes differ between `before` and `after`, or that
/// only one of them holds.
fn changed(
    before: &BTreeMap<PathBuf, Vec<u8>>,
    after: &BTreeMap<PathBuf, Vec<u8>>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = before.keys().chain(after.keys()).cloned().collect();
    paths.sort();
    paths.dedup();
    paths.retain(|path| before.get(path) != after.get(path));
    paths
}

/// What a connection hears of its request: the loop's answer, or that
/// none came while it waited.
type Heard = Result<Result<(), NotAccepted>, mpsc::RecvTimeoutError>;

/// A request to take `network`, as a connection hands it to the loop,
/// and the answer the connection then waits for; with `waiting` false
/// the connection has gone.
fn request_to_take(
    network: SimNetwork,
    waiting: bool,
) -> (mpsc::Receiver<AcceptRequest>, Option<Running<Heard>>) {
    let (requests, acceptances) = mpsc::channel();
    let (answer, answered) = mpsc::sync_channel(0);
    requests.send(AcceptRequest { network, answer }).unwrap();
    let heard = waiting.then(|| Running::start(move || answered.recv_timeout(DEADLINE)));
    (acceptances, heard)
}

/// The deployed loop, the M7 being the stub: after the tick that found
/// another SIM in the M7, a request that names its network is answered
/// and the network taken. The log says so, the next status carries it as
/// accepted at the time of the word, and of the files under the support
/// directory only the record's has changed: not the state, the latch or
/// the SIM meter.
#[test]
fn the_loop_takes_the_network_and_changes_no_other_file() {
    let mut harness = harness_with_the_stub_m7();
    let support = harness.support_dir();
    let run_dir = RunPaths::under(&support).dir;
    let (control, _retries) = shared();
    run_against(&mut harness, &control, 0, cmlink_document(), |_, _| {});

    let (control, _retries) = shared();
    let document = unnamed_document();
    let (lines, (before, heard, after)) =
        run_against(&mut harness, &control, 600, document, |exit, log| {
            let before = files_under(&support);
            let (acceptances, heard) = request_to_take(unnamed(), true);
            exit.accept_networks(log, &acceptances).unwrap();
            let after = files_under(&support);
            exit.tick(&control, log, false).unwrap();
            (before, heard.unwrap().result(), after)
        });
    assert_eq!(heard, Ok(Ok(())));
    assert_eq!(lines, [SWAPPED, ACCEPTED]);
    let accepted = baseline_of(BaselineOrigin::Accepted, unnamed(), 600);
    assert_eq!(shown_by(&control), accepted);
    assert_eq!(on_disk(&run_dir).status(), &accepted);
    let record = run_dir
        .strip_prefix(&support)
        .unwrap()
        .join(SIM_NETWORK_FILE);
    assert_eq!(changed(&before, &after), [record]);
    assert!(before.len() > 1, "{:?}", before.keys());
}

/// The loop takes nothing at a word it cannot bear out, or one whose
/// asker has gone: the reason goes back, nothing is said, and no file
/// under the support directory changes.
#[test]
fn the_loop_takes_nothing_at_a_word_it_cannot_bear_out_or_no_one_waits_for() {
    let mut harness = harness_with_the_stub_m7();
    let support = harness.support_dir();
    let (control, _retries) = shared();
    // The M7 reports the network on record.
    let (lines, (before, heard, after)) =
        run_against(&mut harness, &control, 0, cmlink_document(), |exit, log| {
            let before = files_under(&support);
            let (acceptances, heard) = request_to_take(unnamed(), true);
            exit.accept_networks(log, &acceptances).unwrap();
            (before, heard.unwrap().result(), files_under(&support))
        });
    assert_eq!(heard, Ok(Err(NotAccepted::NoOtherNetwork)));
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(changed(&before, &after), Vec::<PathBuf>::new());

    // Another SIM is in the M7: a word that names the one on record, and
    // one for the M7's whose asker has gone.
    let (control, _retries) = shared();
    let document = unnamed_document();
    let (lines, (before, heard, after)) =
        run_against(&mut harness, &control, 600, document, |exit, log| {
            let before = files_under(&support);
            let (acceptances, heard) = request_to_take(cmlink(), true);
            exit.accept_networks(log, &acceptances).unwrap();
            let (acceptances, gone) = request_to_take(unnamed(), false);
            assert!(gone.is_none());
            exit.accept_networks(log, &acceptances).unwrap();
            let after = files_under(&support);
            exit.tick(&control, log, false).unwrap();
            (before, heard.unwrap().result(), after)
        });
    assert_eq!(heard, Ok(Err(NotAccepted::ReportChanged)));
    assert_eq!(lines, [SWAPPED]);
    assert_eq!(changed(&before, &after), Vec::<PathBuf>::new());
    assert_eq!(shown_by(&control), swapped_since(600));
}

/// One pass answers every request that waits, in the order they came:
/// the first takes the network, and the second, which names the same one,
/// hears that there is no other than the one on record.
#[test]
fn one_pass_answers_every_request_that_waits_in_the_order_they_came() {
    let mut harness = harness_with_the_stub_m7();
    let (control, _retries) = shared();
    run_against(&mut harness, &control, 0, cmlink_document(), |_, _| {});

    let (control, _retries) = shared();
    let document = unnamed_document();
    let (lines, heard) = run_against(&mut harness, &control, 600, document, |exit, log| {
        let (requests, acceptances) = mpsc::channel();
        let askers: Vec<Running<Heard>> = [unnamed(), unnamed()]
            .into_iter()
            .map(|network| {
                let (answer, answered) = mpsc::sync_channel(0);
                requests.send(AcceptRequest { network, answer }).unwrap();
                Running::start(move || answered.recv_timeout(DEADLINE))
            })
            .collect();
        exit.accept_networks(log, &acceptances).unwrap();
        askers
            .into_iter()
            .map(Running::result)
            .collect::<Vec<Heard>>()
    });
    assert_eq!(heard, [Ok(Ok(())), Ok(Err(NotAccepted::NoOtherNetwork))]);
    assert_eq!(lines, [SWAPPED, ACCEPTED]);
}

/// The loop as the daemon runs it answers a request that waits for it,
/// after its tick: the request is there before the loop is served, when
/// the M7 still reports the SIM on record; the served loop's tick finds
/// the other SIM, and only then is the request answered, so its network
/// is taken at the word of the connection that waits.
#[test]
fn the_served_loop_answers_a_waiting_request_after_its_tick() {
    let mut harness = harness_with_the_stub_m7();
    let run_dir = RunPaths::under(&harness.support_dir()).dir;
    let (control, _retries) = shared();
    run_against(&mut harness, &control, 0, cmlink_document(), |_, _| {});

    let (control, asked) = Control::new();
    let (answer, answered) = mpsc::sync_channel(0);
    control
        .accept
        .try_send(AcceptRequest {
            network: unnamed(),
            answer,
        })
        .unwrap();
    let heard = Running::start(move || answered.recv_timeout(DEADLINE));
    let (ended, acceptor_ended) = mpsc::channel();
    ended.send(()).unwrap();
    // The start's poll and the first tick's find the SIM on record; the
    // served loop's tick finds the one without a name.
    let documents = vec![cmlink_document(), cmlink_document(), unnamed_document()];
    let (lines, stopped, polls) = run_polling_every(
        &mut harness,
        &control,
        Duration::ZERO,
        600,
        documents,
        |exit, log| deployed::serve(exit, log, &control, &acceptor_ended, &asked).unwrap(),
    );
    assert_eq!(polls, 3);
    assert_eq!(stopped, Stopped::AcceptorEnded);
    assert_eq!(heard.result(), Ok(Ok(())));
    assert_eq!(lines, [SWAPPED, ACCEPTED]);
    assert_eq!(
        on_disk(&run_dir).status(),
        &baseline_of(BaselineOrigin::Accepted, unnamed(), 600)
    );
}

// --- The command --------------------------------------------------------

/// The serving status the contract's fixtures hold.
const SERVING: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contract/status-fixtures/serving.json"
));

/// A deployed daemon's status that says `network` of the SIM's network,
/// with `router` its latest poll of the M7.
fn deployed_status(network: SimNetworkStatus, router: RouterReading) -> DaemonReply {
    let status: MacStatusV2 = serde_json::from_slice(SERVING).unwrap();
    let mut parts = status.into_parts();
    parts.sim.network = network;
    parts.router = router;
    DaemonReply::Status(ConsoleStatus::Deployed(Box::new(
        MacStatusV2::new(parts).unwrap(),
    )))
}

/// The status of a daemon whose M7 has reported the SIM without a name
/// since 600 s after [`NOW`], its latest poll 660 s after it.
fn swapped_status() -> DaemonReply {
    deployed_status(swapped_since(600), reported(&unnamed(), 660))
}

/// A stand-in daemon on the harness's control socket. It answers one
/// connection for each of `answers`, in turn, with the protocol line and
/// that reply, and returns the request each connection sent. The command
/// reads both lines of a connection before it closes it.
fn daemon_answering(harness: &Harness, answers: Vec<DaemonReply>) -> Running<Vec<String>> {
    let paths = RunPaths::under(&harness.support_dir());
    fs::create_dir_all(&paths.dir).unwrap();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    let protocol = encode_line(&ProtocolLine::CURRENT, MAX_REPLY_LINE_BYTES).unwrap();
    Running::start(move || {
        answers
            .into_iter()
            .map(|answer| {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(&protocol).unwrap();
                let mut request = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut request)
                    .unwrap();
                stream
                    .write_all(&encode_line(&answer, MAX_REPLY_LINE_BYTES).unwrap())
                    .unwrap();
                request
            })
            .collect()
    })
}

/// What the command prints of a daemon whose M7 has reported the SIM
/// without a name since 600 s after [`NOW`].
const SHOWN: &str = "on record: CMLink (234-30), first reported 2026-10-13 19:20:00 UTC\n\
     the M7 reports: a SIM without a name (234-20), at the daemon's poll of 2026-10-13 19:31:00 UTC\n\
     another network than the one on record since 2026-10-13 19:30:00 UTC\n";

/// The request that names the SIM without a name.
const NAMED: &str = "{\"accept_sim_network\":{\"network\":{\"spn\":null,\"plmn\":{\"mcc\":\"234\",\"mnc\":\"20\"}}}}\n";

const QUESTION: &str = "Take a SIM without a name (234-20) as the SIM's network on record? The carrier check and the billing cycle stay as they are.";

const TAKEN: &str = "taken: a SIM without a name (234-20) is the SIM's network on record now; the console's notice ends with the daemon's next status\n";

/// The command shows the network on record and the one the M7 reports,
/// asks, and names to the daemon the network it showed; with `--yes` it
/// does not ask.
#[test]
fn the_command_shows_both_networks_asks_and_names_the_one_it_showed() {
    assert_eq!(NOW, 1_791_919_200);
    for yes in [false, true] {
        let mut harness = harness();
        let daemon = daemon_answering(
            &harness,
            vec![swapped_status(), DaemonReply::SimNetworkAccepted],
        );
        let outcome = if yes {
            harness.run(&["sim", "accept-network", "--yes"])
        } else {
            harness.console.answers.push_back(Answer::Yes);
            harness.run(&["sim", "accept-network"])
        };
        assert_eq!(daemon.result(), ["\"status\"\n", NAMED]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, format!("{SHOWN}{TAKEN}"));
        assert_eq!(outcome.stderr, "");
        if yes {
            assert!(harness.console.asked.is_empty());
        } else {
            assert_eq!(harness.console.asked, [QUESTION]);
        }
    }
}

/// An answer other than yes sends the daemon nothing more: the status was
/// its only request.
#[test]
fn an_answer_other_than_yes_names_nothing_to_the_daemon() {
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
        let mut harness = harness();
        let daemon = daemon_answering(&harness, vec![swapped_status()]);
        harness.console.answers.push_back(answer);
        let outcome = harness.run(&["sim", "accept-network"]);
        assert_eq!(daemon.result(), ["\"status\"\n"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stdout, SHOWN);
        assert_eq!(outcome.stderr, stderr);
        assert_eq!(harness.console.asked, [QUESTION]);
    }
}

/// With nothing to take in the daemon's status the command shows what
/// there is, says why in a sentence, asks nothing and names nothing to
/// the daemon.
#[test]
fn with_nothing_to_take_the_command_says_why_and_asks_nothing() {
    let undeployed = DaemonReply::Status(ConsoleStatus::NoDeployment(UndeployedStatus::new(
        at(0),
        unreachable(),
    )));
    let no_network =
        "the M7 reports: no network (the daemon's latest poll did not find it attached)\n";
    for (status, stdout, stderr) in [
        (
            undeployed,
            String::new(),
            "mooringctl: there is no deployment yet (`exit init` creates it), so no SIM's network is on record\n",
        ),
        (
            deployed_status(
                baseline_of(BaselineOrigin::NoRecord, cmlink(), 0),
                reported(&cmlink(), 660),
            ),
            "on record: CMLink (234-30), first reported 2026-10-13 19:20:00 UTC\n\
             the M7 reports: CMLink (234-30), at the daemon's poll of 2026-10-13 19:31:00 UTC\n"
                .to_owned(),
            "mooringctl: no network was taken: there is no network other than the one on record\n",
        ),
        (
            deployed_status(
                SimNetworkStatus {
                    origin: BaselineOrigin::Recorded,
                    baseline: None,
                },
                unreachable(),
            ),
            format!("on record: no network yet\n{no_network}"),
            "mooringctl: no network was taken: there is no network other than the one on record\n",
        ),
        (
            deployed_status(
                baseline_of(BaselineOrigin::Accepted, unnamed(), 700),
                reported(&unnamed(), 760),
            ),
            "on record: a SIM without a name (234-20), taken at the operator's word 2026-10-13 19:31:40 UTC\n\
             the M7 reports: a SIM without a name (234-20), at the daemon's poll of 2026-10-13 19:32:40 UTC\n"
                .to_owned(),
            "mooringctl: no network was taken: there is no network other than the one on record\n",
        ),
        (
            deployed_status(swapped_since(600), unreachable()),
            format!(
                "on record: CMLink (234-30), first reported 2026-10-13 19:20:00 UTC\n\
                 {no_network}\
                 another network than the one on record since 2026-10-13 19:30:00 UTC\n"
            ),
            "mooringctl: no network was taken: the latest poll of the M7 did not find it attached\n",
        ),
        (
            deployed_status(swapped_since(600), reported(&third(), 660)),
            "on record: CMLink (234-30), first reported 2026-10-13 19:20:00 UTC\n\
             the M7 reports: Other (234-15), at the daemon's poll of 2026-10-13 19:31:00 UTC\n\
             another network than the one on record since 2026-10-13 19:30:00 UTC\n"
                .to_owned(),
            "mooringctl: no network was taken: the M7 no longer reports the network that was to be taken\n",
        ),
    ] {
        let mut harness = harness();
        let daemon = daemon_answering(&harness, vec![status]);
        let outcome = harness.run(&["sim", "accept-network", "--yes"]);
        assert_eq!(daemon.result(), ["\"status\"\n"]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{stderr}");
        assert_eq!(outcome.stdout, stdout);
        assert_eq!(outcome.stderr, stderr);
        assert!(harness.console.asked.is_empty());
    }
}

/// Each refusal of the daemon is reported in its own sentence, and a
/// reply to another request is refused, at the status and at the word.
#[test]
fn each_refusal_of_the_daemon_is_reported_in_its_sentence() {
    let refused = |reason| DaemonReply::Refused { reason };
    let other_request = "mooringctl: the daemon answered with a reply to another request\n";
    // At the status.
    for (answer, stderr) in [
        (
            refused(Refusal::NoStatusYet),
            "mooringctl: the daemon refused the request: its first poll of the M7 has not finished yet\n",
        ),
        (DaemonReply::RetryQueued, other_request),
        (DaemonReply::SimNetworkAccepted, other_request),
    ] {
        let mut harness = harness();
        let daemon = daemon_answering(&harness, vec![answer]);
        let outcome = harness.run(&["sim", "accept-network", "--yes"]);
        assert_eq!(daemon.result(), ["\"status\"\n"]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{stderr}");
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, stderr);
    }
    // At the word.
    for (answer, stderr) in [
        (
            refused(Refusal::NoOtherSimNetwork),
            "mooringctl: the daemon refused the request: there is no network other than the one on record\n",
        ),
        (
            refused(Refusal::M7NotAttached),
            "mooringctl: the daemon refused the request: the latest poll of the M7 did not find it attached\n",
        ),
        (
            refused(Refusal::SimNetworkReportChanged),
            "mooringctl: the daemon refused the request: the M7 no longer reports the network that was to be taken\n",
        ),
        (
            refused(Refusal::LoopBusy),
            "mooringctl: the daemon refused the request: its loop did not come to the request in time; nothing was changed, try again\n",
        ),
        (
            refused(Refusal::NotDeployed),
            "mooringctl: the daemon refused the request: there is no deployment yet (`exit init` creates it)\n",
        ),
        (swapped_status(), other_request),
        (DaemonReply::RetryQueued, other_request),
    ] {
        let mut harness = harness();
        let daemon = daemon_answering(&harness, vec![swapped_status(), answer]);
        let outcome = harness.run(&["sim", "accept-network", "--yes"]);
        assert_eq!(daemon.result(), ["\"status\"\n", NAMED]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{stderr}");
        assert_eq!(outcome.stdout, SHOWN);
        assert_eq!(outcome.stderr, stderr);
    }
}

/// Without a daemon the command says that it is not running.
#[test]
fn without_a_daemon_the_command_says_that_it_is_not_running() {
    let mut harness = harness();
    let socket = RunPaths::under(&harness.support_dir()).socket;
    let outcome = harness.run(&["sim", "accept-network", "--yes"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the Mooring daemon is not running (nothing listens on {})\n",
            socket.display()
        )
    );
}

/// A reason is one sentence, whether the command found it in the status
/// or the daemon refused with it.
#[test]
fn a_reason_is_the_same_sentence_from_the_command_and_from_the_daemon() {
    for (reason, refusal, sentence) in REASONS {
        assert_eq!(reason.to_string(), sentence);
        assert_eq!(refusal_text(refusal), sentence);
        assert_eq!(Refusal::from(reason), refusal);
    }
}
