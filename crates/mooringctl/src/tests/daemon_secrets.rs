// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's secret store (`daemon::secrets`, design §10.1): reads on
//! threads of their own, waited for at most a given time, against a fake
//! keychain whose reads wait until the test answers them; and the daemon
//! opened on that store while the keychain answers nothing, as a new
//! build's first reads do while macOS asks at the Mac's screen.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_daemon_core::status::{DownReason, ExitState};
use mooring_model::secret::{RouterAdminPassword, SecretEntry, SecretMaterial, SecretRef};
use mooring_store::{InMemorySecretStore, ReaderFault, SecretStore, SecretStoreError};

use super::deployed::{CARRIER, deployed, published, shared, statuses};
use super::support::PASSWORD;
use crate::cli::{Cli, Command};
use crate::daemon::deployed::Deployed;
use crate::daemon::secrets::{DaemonSecrets, Read};
use crate::daemon::{Intervals, LoopState, RunPaths};
use crate::keychain::CommandSecrets;

/// The wait of the tests whose reads are answered at once: long enough
/// that a loaded machine answers within it.
const PLENTY: Duration = Duration::from_secs(60);

/// The wait of the tests whose reads are held: short, so the test does
/// not wait long for the store to give up.
const SHORT: Duration = Duration::from_millis(50);

/// A keychain whose held reads wait until the test releases them, and
/// whose panicking ones panic; it answers from `materials` and records
/// each read begun.
#[derive(Default)]
struct Keychain {
    materials: Mutex<InMemorySecretStore>,
    holds: Mutex<Holds>,
    released: Condvar,
    panicking: Mutex<BTreeSet<SecretRef>>,
    begun: Mutex<Vec<SecretRef>>,
}

/// The reads the keychain holds: all, or those of the references named.
#[derive(Default)]
struct Holds {
    all: bool,
    refs: BTreeSet<SecretRef>,
}

impl Keychain {
    /// The keychain holding `materials`, whose reads are all held.
    fn holding_all(materials: InMemorySecretStore) -> Self {
        let keychain = Self {
            materials: Mutex::new(materials),
            ..Self::default()
        };
        keychain.holds.lock().unwrap().all = true;
        keychain
    }

    fn read(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError> {
        self.begun.lock().unwrap().push(secret_ref.clone());
        let mut holds = self.holds.lock().unwrap();
        while holds.all || holds.refs.contains(secret_ref) {
            holds = self.released.wait(holds).unwrap();
        }
        drop(holds);
        assert!(
            !self.panicking.lock().unwrap().contains(secret_ref),
            "the test's read of {secret_ref} panics"
        );
        self.materials.lock().unwrap().get(secret_ref)
    }

    fn hold(&self, secret_ref: &SecretRef) {
        self.holds.lock().unwrap().refs.insert(secret_ref.clone());
    }

    fn release(&self, secret_ref: &SecretRef) {
        self.holds.lock().unwrap().refs.remove(secret_ref);
        self.released.notify_all();
    }

    fn release_all(&self) {
        *self.holds.lock().unwrap() = Holds::default();
        self.released.notify_all();
    }

    fn panic_on(&self, secret_ref: &SecretRef) {
        self.panicking.lock().unwrap().insert(secret_ref.clone());
    }

    fn begun(&self) -> Vec<SecretRef> {
        self.begun.lock().unwrap().clone()
    }
}

/// The read the store makes: the keychain's.
fn reader(keychain: &Arc<Keychain>) -> Arc<Read> {
    let keychain = Arc::clone(keychain);
    Arc::new(move |secret_ref: &SecretRef| keychain.read(secret_ref))
}

/// The keychain with the M7's admin password, its reads answered at once.
fn with_password() -> Arc<Keychain> {
    let mut materials = InMemorySecretStore::default();
    materials.put(password_entry()).unwrap();
    Arc::new(Keychain {
        materials: Mutex::new(materials),
        ..Keychain::default()
    })
}

fn password_entry() -> SecretEntry {
    SecretEntry::new(
        SecretRef::RouterAdmin,
        SecretMaterial::RouterAdminPassword(RouterAdminPassword::parse(PASSWORD).unwrap()),
    )
    .unwrap()
}

/// The password's text, when `answer` is the M7's password.
fn password_text(answer: Result<SecretMaterial, SecretStoreError>) -> String {
    match answer.unwrap() {
        material @ SecretMaterial::RouterAdminPassword(_) => material.encode().to_string(),
        other => panic!("not the M7's password: {other:?}"),
    }
}

fn unanswered(secret_ref: SecretRef) -> SecretStoreError {
    SecretStoreError::Unanswered { secret_ref }
}

/// What `get` gives once the waiting read of `secret_ref` has its answer:
/// until then each `get` is `Unanswered` (for at most 5 s).
fn answer_after_release(
    store: &DaemonSecrets<InMemorySecretStore>,
    secret_ref: &SecretRef,
) -> Result<SecretMaterial, SecretStoreError> {
    let begun = Instant::now();
    loop {
        match store.get(secret_ref) {
            Err(SecretStoreError::Unanswered { .. })
                if begun.elapsed() < Duration::from_secs(5) =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            answer => return answer,
        }
    }
}

/// `mooringctl daemon` gets the daemon's store, which waits 3 s for each
/// answer; a command run at the Mac gets the login keychain itself, whose
/// reads wait for the operator's answer. Nothing here reads the keychain.
#[test]
fn only_the_daemon_reads_without_waiting_for_the_screen() {
    match CommandSecrets::for_command(&Command::Daemon) {
        CommandSecrets::Daemon(store) => {
            assert_eq!(format!("{store:?}"), "DaemonSecrets { within: 3s, .. }");
        }
        other @ CommandSecrets::Login(_) => panic!("{other:?}"),
    }
    for args in [
        ["mooringctl", "status"].as_slice(),
        ["mooringctl", "router", "status", "--interface", "en9"].as_slice(),
    ] {
        let command = Cli::try_parse_from(args).unwrap().command;
        assert!(
            matches!(
                CommandSecrets::for_command(&command),
                CommandSecrets::Login(_)
            ),
            "{args:?}"
        );
    }
}

/// A read answered within the wait gives the keychain's answer, a
/// material or an error alike, and keeps nothing: the next read of the
/// same reference reads again.
#[test]
fn an_answer_within_the_wait_is_the_keychains_own() {
    let keychain = with_password();
    let store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), PLENTY);
    assert_eq!(password_text(store.get(&SecretRef::RouterAdmin)), PASSWORD);
    assert_eq!(
        store.get(&SecretRef::PortalPullToken).unwrap_err(),
        SecretStoreError::SecretMissing {
            secret_ref: SecretRef::PortalPullToken,
        }
    );
    assert_eq!(password_text(store.get(&SecretRef::RouterAdmin)), PASSWORD);
    assert_eq!(
        keychain.begun(),
        [
            SecretRef::RouterAdmin,
            SecretRef::PortalPullToken,
            SecretRef::RouterAdmin
        ]
    );
}

/// A read the keychain has not answered within the wait is `Unanswered`
/// and goes on. Until its answer comes, each read of that reference is
/// `Unanswered` at once and begins none; the answer is the next read's,
/// and the read after it reads again.
#[test]
fn a_read_not_answered_within_the_wait_goes_on_and_its_answer_is_the_next_reads() {
    let within = Duration::from_secs(2);
    let keychain = with_password();
    keychain.hold(&SecretRef::RouterAdmin);
    let store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), within);
    let asked = Instant::now();
    assert_eq!(
        store.get(&SecretRef::RouterAdmin).unwrap_err(),
        unanswered(SecretRef::RouterAdmin)
    );
    assert!(asked.elapsed() >= within);
    let again = Instant::now();
    assert_eq!(
        store.get(&SecretRef::RouterAdmin).unwrap_err(),
        unanswered(SecretRef::RouterAdmin)
    );
    // At once: the second read does not wait out the wait again.
    assert!(again.elapsed() < within / 2, "{:?}", again.elapsed());
    assert_eq!(keychain.begun(), [SecretRef::RouterAdmin]);
    keychain.release(&SecretRef::RouterAdmin);
    assert_eq!(
        password_text(answer_after_release(&store, &SecretRef::RouterAdmin)),
        PASSWORD
    );
    assert_eq!(keychain.begun(), [SecretRef::RouterAdmin]);
    assert_eq!(password_text(store.get(&SecretRef::RouterAdmin)), PASSWORD);
    assert_eq!(
        keychain.begun(),
        [SecretRef::RouterAdmin, SecretRef::RouterAdmin]
    );
}

/// One reference's waiting read holds up no other reference's.
#[test]
fn a_waiting_read_holds_up_no_other_reference() {
    let keychain = with_password();
    keychain.hold(&SecretRef::PortalPullToken);
    let store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), SHORT);
    assert_eq!(
        store.get(&SecretRef::PortalPullToken).unwrap_err(),
        unanswered(SecretRef::PortalPullToken)
    );
    assert_eq!(password_text(store.get(&SecretRef::RouterAdmin)), PASSWORD);
    keychain.release_all();
}

/// A read whose thread ends without an answer is `ReaderFailed{Ended}`,
/// within the wait or after it, and leaves nothing waiting: the next read
/// reads again.
#[test]
fn a_read_whose_thread_ends_without_an_answer_fails_and_the_next_reads_again() {
    let keychain = with_password();
    keychain.panic_on(&SecretRef::RouterAdmin);
    let store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), PLENTY);
    let ended = SecretStoreError::ReaderFailed {
        secret_ref: SecretRef::RouterAdmin,
        fault: ReaderFault::Ended,
    };
    assert_eq!(store.get(&SecretRef::RouterAdmin).unwrap_err(), ended);
    let store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), SHORT);
    keychain.hold(&SecretRef::RouterAdmin);
    assert_eq!(
        store.get(&SecretRef::RouterAdmin).unwrap_err(),
        unanswered(SecretRef::RouterAdmin)
    );
    keychain.release(&SecretRef::RouterAdmin);
    assert_eq!(
        answer_after_release(&store, &SecretRef::RouterAdmin).unwrap_err(),
        ended
    );
    keychain.panicking.lock().unwrap().clear();
    assert_eq!(password_text(store.get(&SecretRef::RouterAdmin)), PASSWORD);
    assert_eq!(keychain.begun().len(), 3);
}

/// A read whose thread cannot start is `ReaderFailed{NotStarted}` with
/// the error's kind; nothing is read and nothing left waiting.
#[test]
fn a_read_whose_thread_cannot_start_fails_with_its_kind() {
    let keychain = with_password();
    let store = DaemonSecrets::spawning(
        reader(&keychain),
        InMemorySecretStore::default(),
        PLENTY,
        |_| Err(io::Error::from(io::ErrorKind::WouldBlock)),
    );
    for _ in 0..2 {
        assert_eq!(
            store.get(&SecretRef::RouterAdmin).unwrap_err(),
            SecretStoreError::ReaderFailed {
                secret_ref: SecretRef::RouterAdmin,
                fault: ReaderFault::NotStarted(io::ErrorKind::WouldBlock),
            }
        );
    }
    assert!(keychain.begun().is_empty());
}

/// Writes go to the inner store, and drop the waiting read of their
/// reference, whose answer would be of the item before them: the next
/// read reads again.
#[test]
fn writes_go_to_the_inner_store_and_drop_their_references_waiting_read() {
    let keychain = with_password();
    keychain.hold(&SecretRef::RouterAdmin);
    let mut store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), SHORT);
    let waiting = |store: &DaemonSecrets<InMemorySecretStore>| {
        assert_eq!(
            store.get(&SecretRef::RouterAdmin).unwrap_err(),
            unanswered(SecretRef::RouterAdmin)
        );
    };
    waiting(&store);
    store.put(password_entry()).unwrap();
    waiting(&store);
    assert_eq!(keychain.begun().len(), 2);
    store.delete(&SecretRef::RouterAdmin).unwrap();
    assert_eq!(
        store.delete(&SecretRef::RouterAdmin).unwrap_err(),
        SecretStoreError::SecretMissing {
            secret_ref: SecretRef::RouterAdmin,
        }
    );
    waiting(&store);
    assert_eq!(keychain.begun().len(), 3);
    keychain.release_all();
}

/// The fault of 2026-11-15: a new build's first read of the M7's password
/// waited on macOS's question at the Mac's screen and held the daemon
/// before its first status. On the daemon's store, with every read held,
/// the exit opens and its first tick publishes the exit down for its
/// secrets and the M7's poll as failed on the Mac, the log naming the
/// read; once the keychain answers, the engine starts.
#[test]
fn a_keychain_that_answers_nothing_holds_up_no_status_and_its_answers_are_taken() {
    let mut harness = deployed();
    for _ in 0..200 {
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
    }
    statuses(&harness);
    let support = harness.support_dir();
    fs::create_dir_all(RunPaths::under(&support).dir).unwrap();
    let keychain = Arc::new(Keychain::holding_all(std::mem::take(&mut harness.secrets)));
    let mut store = DaemonSecrets::new(reader(&keychain), InMemorySecretStore::default(), SHORT);
    let (control, _retries) = shared();
    let down = ExitState::Down {
        reason: DownReason::SecretsUnavailable,
    };
    let log = harness.with_env_on(Some(&mut store), |env| {
        let mut log = Vec::new();
        let mut exit = Deployed::open(
            env,
            &support,
            &mut log,
            LoopState::default(),
            Intervals::DAEMON,
        )
        .unwrap();
        assert_eq!(exit.tick(&control, &mut log, false).unwrap(), down);
        let status = published(&control);
        let parts = status.parts();
        assert_eq!(parts.exit.state, down);
        assert!(
            matches!(
                parts.router,
                RouterReading::Unavailable {
                    reason: RouterUnavailableReason::LocalFailure,
                    ..
                }
            ),
            "{:?}",
            parts.router
        );
        keychain.release_all();
        let begun = Instant::now();
        let mut state = exit.tick(&control, &mut log, false).unwrap();
        while state == down && begun.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(5));
            state = exit.tick(&control, &mut log, false).unwrap();
        }
        assert_eq!(state, ExitState::Starting);
        log
    });
    let log = String::from_utf8(log).unwrap();
    assert!(
        log.contains(
            "router poll failed: the keychain failed: the keychain has not yet answered \
             the read of router/admin (macOS may be asking at the Mac's screen)"
        ),
        "{log}"
    );
}
