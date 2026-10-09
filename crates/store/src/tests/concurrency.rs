// SPDX-License-Identifier: GPL-3.0-or-later

//! Concurrent writers and readers are serialised by `state.lock`.
//!
//! Every thread uses its own `Store` value, and every operation opens its
//! own lock descriptor, so threads exclude each other as processes do.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

use mooring_model::counters::ConfigGeneration;
use mooring_model::exit::FlowCap;

use super::builders::initialised;
use super::store_error;
use crate::error::StoreErrorKind;
use crate::store::Store;

/// How long a thread that should be blocked is given to finish anyway.
const BLOCKED_GRACE: Duration = Duration::from_millis(500);

/// Starts a config update that stays inside its change function, holding
/// the lock, until `release` is sent. Returns once the change is running.
fn hold_the_lock(
    store: &Store,
    expected: ConfigGeneration,
) -> (mpsc::Sender<()>, thread::JoinHandle<ConfigGeneration>) {
    let (inside_tx, inside_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder = store.clone();
    let handle = thread::spawn(move || {
        holder
            .update_config(expected, |parts| {
                inside_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, Infallible>(parts)
            })
            .unwrap()
            .deployment
            .config_generation()
    });
    inside_rx.recv().unwrap();
    (release_tx, handle)
}

#[test]
fn a_writer_holds_the_lock_for_its_whole_read_modify_write() {
    let (_dir, store, state) = initialised();
    let read = state.deployment.config_generation();
    let (release, holder) = hold_the_lock(&store, read);

    // A second writer that read the same generation must wait, then see
    // the first writer's result and fail the compare-and-swap.
    let (done_tx, done_rx) = mpsc::channel();
    let contender = store.clone();
    let second = thread::spawn(move || {
        let result = contender.update_config(read, Ok::<_, Infallible>);
        done_tx.send(()).unwrap();
        result
    });
    assert!(
        done_rx.recv_timeout(BLOCKED_GRACE).is_err(),
        "the second writer ran while the first held the lock"
    );

    release.send(()).unwrap();
    assert_eq!(holder.join().unwrap().get(), 2);
    let error = store_error(second.join().unwrap().unwrap_err());
    assert_eq!(error.kind(), StoreErrorKind::GenerationConflict);
    assert_eq!(
        store.load().unwrap().deployment.config_generation().get(),
        2
    );
}

#[test]
fn readers_wait_for_a_write_in_progress() {
    let (_dir, store, state) = initialised();
    let (release, holder) = hold_the_lock(&store, state.deployment.config_generation());

    let (done_tx, done_rx) = mpsc::channel();
    let reader = store.clone();
    let read = thread::spawn(move || {
        let loaded = reader.load().unwrap();
        done_tx.send(()).unwrap();
        loaded
    });
    assert!(
        done_rx.recv_timeout(BLOCKED_GRACE).is_err(),
        "a reader ran while a writer held the lock"
    );

    release.send(()).unwrap();
    holder.join().unwrap();
    // The reader only ever sees the durable result of the write.
    assert_eq!(read.join().unwrap().deployment.config_generation().get(), 2);
}

#[test]
fn concurrent_writers_never_lose_an_update() {
    const WRITERS: usize = 4;
    const UPDATES: usize = 8;
    let (_dir, store, state) = initialised();
    let start_cap = state.deployment.exit().flow_cap.get();
    let start = Arc::new(Barrier::new(WRITERS + 1));
    let stop = Arc::new(AtomicBool::new(false));

    // A reader that ignores the lock, as a crash or a foreign tool would,
    // must still only ever find complete documents.
    let raw_reader = {
        let path = store.state_path();
        let stop = Arc::clone(&stop);
        let start = Arc::clone(&start);
        thread::spawn(move || {
            start.wait();
            let mut reads = 0_u32;
            while !stop.load(Ordering::Relaxed) {
                let bytes = fs::read(&path).unwrap();
                crate::migrate::parse(&bytes).unwrap();
                reads += 1;
            }
            reads
        })
    };

    let writers: Vec<_> = (0..WRITERS)
        .map(|_| {
            let store = store.clone();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                let mut won = Vec::new();
                while won.len() < UPDATES {
                    let read = store.load().unwrap().deployment.config_generation();
                    let result = store.update_config(read, |mut parts| {
                        let cap = parts.exit.flow_cap.get() + 1;
                        parts.exit.flow_cap = FlowCap::new(cap).unwrap();
                        Ok::<_, Infallible>(parts)
                    });
                    match result {
                        Ok(next) => won.push(next.deployment.config_generation().get()),
                        Err(error) => assert_eq!(
                            store_error(error).kind(),
                            StoreErrorKind::GenerationConflict
                        ),
                    }
                }
                won
            })
        })
        .collect();

    let mut generations = BTreeSet::new();
    for writer in writers {
        for generation in writer.join().unwrap() {
            assert!(
                generations.insert(generation),
                "generation {generation} won twice"
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    assert!(raw_reader.join().unwrap() > 0);

    let total = WRITERS * UPDATES;
    let expected: BTreeSet<u64> = (2..=(1 + total as u64)).collect();
    assert_eq!(generations, expected);
    let last = store.load().unwrap();
    assert_eq!(last.deployment.config_generation().get(), 1 + total as u64);
    assert_eq!(
        last.deployment.exit().flow_cap.get(),
        start_cap + total as u32,
        "every increment survived"
    );
}
