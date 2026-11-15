// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's secret store (design §10.1, §12): the login keychain, read
//! so that a read macOS has not answered holds nothing else up.
//!
//! `mooringctl` is signed ad hoc, so each build is new to the keychain:
//! before a new build first reads an item, macOS asks at the Mac's screen
//! whether to allow it, and the read waits until the operator answers
//! (Always Allow, then the login password). Read on the loop's thread,
//! such a read held the daemon before its first poll of the M7, with
//! nothing published or logged, for as long as no one was at the screen.
//!
//! So each read runs on a thread of its own, and the daemon waits at most
//! [`ANSWER_WITHIN`] for its answer. A read not answered by then is
//! [`SecretStoreError::Unanswered`], and it goes on: the exit is
//! `Down(SecretsUnavailable)`, the M7's poll fails (`LocalFailure`, the
//! log naming the read) and the payment pull waits, while the loop goes
//! on publishing its status. The read's answer is the next read's of the
//! same reference. Until it comes, each read of that reference is
//! `Unanswered` at once and starts none, so macOS asks once and at most
//! one read per reference is in flight; the references the daemon reads
//! bound the threads that wait.
//!
//! launchd's apply job (`apply --pending`, design §13.6) reads through the
//! same store, since no one watches it either: a node apply whose secrets
//! are not answered fails, each node after it fails at once on the same
//! waiting read, and the run ends, releasing its lock, instead of waiting
//! with it until someone answers. A read still waiting ends with the
//! process; the next run reads again.
//!
//! Writes are the inner store's own, made on the caller's thread with no
//! wait (the daemon writes no secret); a write drops the waiting read of
//! its reference, whose answer would be the item from before it.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::Duration;

use mooring_model::secret::{SecretEntry, SecretMaterial, SecretRef};
use mooring_store::{ReaderFault, SecretStore, SecretStoreError};

/// How long the daemon waits for the keychain to answer a read: far longer
/// than a read of an allowed item takes, and short enough that a question
/// at the Mac's screen costs the loop one short wait per item.
pub(crate) const ANSWER_WITHIN: Duration = Duration::from_secs(3);

/// A read of the keychain, made on a thread of its own.
pub(crate) type Read = dyn Fn(&SecretRef) -> Result<SecretMaterial, SecretStoreError> + Send + Sync;

/// Starts the thread that makes a read.
pub(crate) type Spawn = fn(Box<dyn FnOnce() + Send>) -> io::Result<()>;

/// A read's answer.
type Answer = Result<SecretMaterial, SecretStoreError>;

/// The daemon's secret store: it reads through `read` on threads of their
/// own and writes through `writes`.
pub(crate) struct DaemonSecrets<W> {
    read: Arc<Read>,
    writes: W,
    within: Duration,
    spawn: Spawn,
    /// The reads the keychain had not answered within the wait, by
    /// reference, each with the channel its answer comes on.
    waiting: RefCell<BTreeMap<SecretRef, Receiver<Answer>>>,
}

impl<W> fmt::Debug for DaemonSecrets<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonSecrets")
            .field("within", &self.within)
            .finish_non_exhaustive()
    }
}

impl<W> DaemonSecrets<W> {
    /// The store that reads through `read`, waiting at most `within` for
    /// each answer, and writes through `writes`.
    pub(crate) fn new(read: Arc<Read>, writes: W, within: Duration) -> Self {
        Self::spawning(read, writes, within, spawn_reader)
    }

    /// [`DaemonSecrets::new`], with `spawn` starting the reads' threads.
    pub(crate) fn spawning(read: Arc<Read>, writes: W, within: Duration, spawn: Spawn) -> Self {
        Self {
            read,
            writes,
            within,
            spawn,
            waiting: RefCell::new(BTreeMap::new()),
        }
    }
}

fn unanswered(secret_ref: &SecretRef) -> SecretStoreError {
    SecretStoreError::Unanswered {
        secret_ref: secret_ref.clone(),
    }
}

/// Starts a named thread for a read. It is not joined: a read the keychain
/// never answers keeps its thread until the daemon stops.
fn spawn_reader(read: Box<dyn FnOnce() + Send>) -> io::Result<()> {
    thread::Builder::new()
        .name("mooring-keychain".to_owned())
        .spawn(read)
        .map(drop)
}

fn failed(secret_ref: &SecretRef, fault: ReaderFault) -> SecretStoreError {
    SecretStoreError::ReaderFailed {
        secret_ref: secret_ref.clone(),
        fault,
    }
}

impl<W: SecretStore> SecretStore for DaemonSecrets<W> {
    /// The waiting read's answer, if it has come; `Unanswered` at once
    /// while it has not. Otherwise a new read, whose answer is given if it
    /// comes within the wait.
    fn get(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError> {
        let mut waiting = self.waiting.borrow_mut();
        if let Some(answer) = waiting.get(secret_ref) {
            let answered = match answer.try_recv() {
                Err(TryRecvError::Empty) => return Err(unanswered(secret_ref)),
                Ok(answered) => answered,
                Err(TryRecvError::Disconnected) => Err(failed(secret_ref, ReaderFault::Ended)),
            };
            waiting.remove(secret_ref);
            return answered;
        }
        let (send, answer) = mpsc::sync_channel(1);
        let read = Arc::clone(&self.read);
        let owned = secret_ref.clone();
        (self.spawn)(Box::new(move || {
            // No one receives the answer once the store is gone with the
            // daemon.
            let _ = send.send(read(&owned));
        }))
        .map_err(|error| failed(secret_ref, ReaderFault::NotStarted(error.kind())))?;
        match answer.recv_timeout(self.within) {
            Ok(answered) => answered,
            Err(RecvTimeoutError::Timeout) => {
                waiting.insert(secret_ref.clone(), answer);
                Err(unanswered(secret_ref))
            }
            Err(RecvTimeoutError::Disconnected) => Err(failed(secret_ref, ReaderFault::Ended)),
        }
    }

    fn put(&mut self, entry: SecretEntry) -> Result<(), SecretStoreError> {
        self.waiting.get_mut().remove(&entry.secret_ref());
        self.writes.put(entry)
    }

    fn delete(&mut self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        self.waiting.get_mut().remove(secret_ref);
        self.writes.delete(secret_ref)
    }
}
