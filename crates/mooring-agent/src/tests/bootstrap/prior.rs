// SPDX-License-Identifier: GPL-3.0-or-later

//! A host that ran Mooring before (design §13.2): `Bootstrap` refuses it,
//! before it changes anything, when it holds state only a node's use
//! leaves. Each [`PriorState`] is refused, on a host this adoption has
//! bootstrapped and on one it has not, and the first in order is the one
//! reported. A location counts whatever it holds, other than an empty
//! directory where a directory belongs, and whatever the names in it; a
//! state root that is not a directory, or a location that cannot be read,
//! stops `Bootstrap` too. A retry of the same adoption, after the units and
//! the uploads have run, finds none of it and goes through.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    AgentError, Generation, HostProfile, IoOp, LineRequest, PriorState, Role, Sha256Hex, UsageMonth,
};

use super::world::{Host, keys, new_key};
use crate::bootstrap::prior_state;
use crate::paths::Paths;
use crate::tests::serve::{ask, frame};
use crate::tests::{EACCES, ModeFault, temporary_of};
use crate::txn::stage::{XRAY, store_path};
use crate::txn::{Why, revert_pending};

/// A file at `path`, with its parents. The check reads no file, so what it
/// holds does not matter.
fn put(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "{}").unwrap();
}

/// Leaves `state` on the host, as a node's use would.
fn leave(paths: &Paths, state: PriorState) {
    match state {
        PriorState::Generations => {
            fs::create_dir_all(paths.generation(Generation::new(7))).unwrap();
            symlink("gen-7", paths.current()).unwrap();
        }
        PriorState::Transactions => put(&paths.txn_record(Generation::new(7))),
        PriorState::Usage => put(&paths.usage_month("2026-10".parse::<UsageMonth>().unwrap())),
        PriorState::Halted => put(&paths.halted()),
        PriorState::Holds => put(&paths.holds()),
        PriorState::StopRequest => put(&paths.stop_request()),
        PriorState::MacReport => put(&paths.mac_report()),
    }
}

/// What is at a path: a directory and its mode, a file's mode and bytes,
/// or a link's target.
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory(u32),
    File(u32, Vec<u8>),
    Link(PathBuf),
}

/// Everything under the scratch root, links not followed.
fn tree(paths: &Paths) -> BTreeMap<PathBuf, Entry> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![paths.at("/")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o7777;
            let entry = if meta.file_type().is_symlink() {
                Entry::Link(fs::read_link(&path).unwrap())
            } else if meta.is_dir() {
                dirs.push(path.clone());
                Entry::Directory(mode)
            } else {
                Entry::File(mode, fs::read(&path).unwrap())
            };
            found.insert(path, entry);
        }
    }
    found
}

/// A host this adoption bootstrapped once: its `host-key.json` makes a
/// second run converge. A test copies it for each case ([`Host::copy`]).
fn bootstrapped() -> Host {
    let host = Host::new();
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()));
    host
}

/// `Bootstrap` on `host` is refused for `found`, with no tool run and the
/// host as it was, so the key that logged in still does.
fn assert_refused(host: &Host, found: PriorState, case: &str) {
    let before = tree(&host.paths);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::HostRanMooring { found }),
        "{case}"
    );
    assert!(node.calls().is_empty(), "{case}: {:#?}", node.calls());
    assert_eq!(tree(&host.paths), before, "{case}");
}

/// `Bootstrap` with the stand-in's keys, expecting the agent
/// `expected_agent_sha`.
fn request(expected_agent_sha: Sha256Hex) -> LineRequest {
    let (bootstrap_pubkey, ops_pubkey) = keys();
    LineRequest::Bootstrap {
        expected_agent_sha,
        bootstrap_pubkey,
        ops_pubkey,
    }
}

#[test]
fn each_prior_state_is_refused_before_anything_changes() {
    let fresh = Host::new();
    let bootstrapped = bootstrapped();
    for &state in PriorState::ALL {
        for (template, case) in [
            (&fresh, "not bootstrapped"),
            (&bootstrapped, "bootstrapped"),
        ] {
            let host = template.copy();
            leave(&host.paths, state);
            assert_refused(&host, state, &format!("{state:?} on a host {case}"));
        }
    }
}

/// The order `Bootstrap` looks in, as design §13.2 gives it.
const ORDER: [PriorState; 7] = [
    PriorState::Generations,
    PriorState::Transactions,
    PriorState::Usage,
    PriorState::Halted,
    PriorState::Holds,
    PriorState::StopRequest,
    PriorState::MacReport,
];

/// A host holding several is refused for the first in the design's order,
/// in the bootstrap role's reply.
#[test]
fn the_first_prior_state_held_is_reported() {
    assert_eq!(PriorState::ALL, ORDER.as_slice());
    let bootstrapped = bootstrapped();
    for (index, &first) in ORDER.iter().enumerate() {
        let host = bootstrapped.copy();
        for &state in &ORDER[index..] {
            leave(&host.paths, state);
        }
        let node = host.node();
        assert_eq!(
            ask(
                &host.paths,
                &node,
                Role::Bootstrap,
                frame(&request(host.sha))
            ),
            Err(AgentError::HostRanMooring { found: first }),
            "{first:?}"
        );
        assert!(node.calls().is_empty(), "{first:?}");
    }
}

/// What a case does to a host bootstrapped once.
type Shape = fn(&Paths);

/// Replaces the empty directory at `path` with a file.
fn file_for_dir(path: &Path) {
    fs::remove_dir(path).unwrap();
    put(path);
}

/// Replaces the empty directory at `path` with a link to another empty
/// directory.
fn link_for_dir(paths: &Paths, path: &Path) {
    fs::remove_dir(path).unwrap();
    let elsewhere = paths.at("/srv/empty");
    fs::create_dir_all(&elsewhere).unwrap();
    symlink(elsewhere, path).unwrap();
}

/// A location counts whatever it holds, its links never followed, other
/// than an empty directory where a directory belongs; leftovers of a write
/// or a swap count too.
#[test]
fn whatever_a_location_holds_counts() {
    let cases: [(&str, Shape, PriorState); 19] = [
        (
            "current alone, dangling",
            |paths| symlink("gen-9", paths.current()).unwrap(),
            PriorState::Generations,
        ),
        (
            "current, a file",
            |paths| put(&paths.current()),
            PriorState::Generations,
        ),
        (
            "current, a directory",
            |paths| fs::create_dir(paths.current()).unwrap(),
            PriorState::Generations,
        ),
        (
            "a generation with no current",
            |paths| fs::create_dir(paths.generation(Generation::new(3))).unwrap(),
            PriorState::Generations,
        ),
        (
            "a swap's leftover link",
            |paths| symlink("gen-3", paths.etc().join("current.swap.4242")).unwrap(),
            PriorState::Generations,
        ),
        (
            "/etc/mooring, a dangling link",
            |paths| {
                fs::remove_dir(paths.etc()).unwrap();
                symlink(paths.at("/nowhere"), paths.etc()).unwrap();
            },
            PriorState::Generations,
        ),
        (
            "/etc/mooring, a link to an empty directory",
            |paths| link_for_dir(paths, &paths.etc()),
            PriorState::Generations,
        ),
        (
            "/etc/mooring, a file",
            |paths| file_for_dir(&paths.etc()),
            PriorState::Generations,
        ),
        (
            "a pending change",
            |paths| put(&paths.pending()),
            PriorState::Transactions,
        ),
        (
            "a record's leftover temporary file",
            |paths| put(&temporary_of(&paths.pending())),
            PriorState::Transactions,
        ),
        (
            "txn, a file",
            |paths| file_for_dir(&paths.txn_dir()),
            PriorState::Transactions,
        ),
        (
            "the accounting alone",
            |paths| put(&paths.accounting()),
            PriorState::Usage,
        ),
        (
            "the accounting's leftover temporary file",
            |paths| put(&temporary_of(&paths.accounting())),
            PriorState::Usage,
        ),
        (
            "usage, a link to an empty directory",
            |paths| link_for_dir(paths, &paths.usage_dir()),
            PriorState::Usage,
        ),
        (
            "halted.json, an empty directory",
            |paths| fs::create_dir(paths.halted()).unwrap(),
            PriorState::Halted,
        ),
        (
            "halted.json, a dangling link",
            |paths| symlink(paths.at("/nowhere"), paths.halted()).unwrap(),
            PriorState::Halted,
        ),
        (
            "the holds' leftover temporary file",
            |paths| put(&temporary_of(&paths.holds())),
            PriorState::Holds,
        ),
        (
            "stop, a file",
            |paths| file_for_dir(&paths.stop_dir()),
            PriorState::StopRequest,
        ),
        (
            "mac-report.json, an empty directory",
            |paths| fs::create_dir(paths.mac_report()).unwrap(),
            PriorState::MacReport,
        ),
    ];
    let bootstrapped = bootstrapped();
    for (case, shape, found) in cases {
        let host = bootstrapped.copy();
        shape(&host.paths);
        assert_refused(&host, found, case);
    }
}

/// A state root that is not a directory is not read through: `Bootstrap`
/// stops before anything, as the layout's convergence would refuse it
/// later, after the packages and the accounts.
#[test]
fn a_state_root_that_is_not_a_directory_stops_bootstrap_before_anything() {
    let cases: [(&str, Shape); 2] = [
        (
            "a link to a directory holding an empty usage directory",
            |paths| {
                let elsewhere = paths.at("/srv/state");
                fs::create_dir_all(elsewhere.join("usage")).unwrap();
                fs::create_dir_all(paths.var_lib().parent().unwrap()).unwrap();
                symlink(elsewhere, paths.var_lib()).unwrap();
            },
        ),
        ("a file", |paths| put(&paths.var_lib())),
    ];
    for (case, shape) in cases {
        let host = Host::new();
        shape(&host.paths);
        let before = tree(&host.paths);
        let node = host.node();
        assert_eq!(
            host.bootstrap(&node),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: None
            }),
            "{case}"
        );
        assert!(node.calls().is_empty(), "{case}: {:#?}", node.calls());
        assert_eq!(tree(&host.paths), before, "{case}");
    }
}

/// Where a case's fault is set: one of the agent's locations.
type Location = fn(&Paths) -> PathBuf;

/// A state root that cannot be examined stops `Bootstrap` before any
/// location is judged, `/etc/mooring` holding a generation included: it is
/// an error, never taken for an absent root.
#[test]
fn a_state_root_that_cannot_be_examined_stops_bootstrap_first() {
    let host = bootstrapped();
    leave(&host.paths, PriorState::Generations);
    let _fault = ModeFault::set(&host.paths.at("/var/lib"), 0o600);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(EACCES)
        })
    );
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
}

/// A location the check cannot read is never taken for an empty one.
#[test]
fn what_the_check_cannot_read_fails_closed() {
    let cases: [(&str, Location, u32); 3] = [
        ("usage, not readable", Paths::usage_dir, 0o300),
        ("/etc/mooring, not readable", Paths::etc, 0o300),
        ("/var/lib/mooring, not searchable", Paths::var_lib, 0o600),
    ];
    let bootstrapped = bootstrapped();
    for (case, location, mode) in cases {
        let host = bootstrapped.copy();
        let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
        let _fault = ModeFault::set(&location(&host.paths), mode);
        let node = host.node();
        assert_eq!(
            host.bootstrap(&node),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: Some(EACCES)
            }),
            "{case}"
        );
        assert!(node.calls().is_empty(), "{case}: {:#?}", node.calls());
        assert_eq!(
            fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
            keys,
            "{case}"
        );
    }
}

/// A retry of the same adoption finds none of this state, after what runs
/// while the node is planned (the watch, the locks, and `txn-recover`,
/// which finds no change pending at boot), and after the uploads and the
/// target check too, which come only once it is adopted: it converges,
/// keeping its host key.
#[test]
fn a_retry_after_the_units_and_uploads_ran_goes_through() {
    let host = bootstrapped();
    let paths = &host.paths;
    for file in [
        paths.watch_status(),
        temporary_of(&paths.watch_status()),
        paths.journal(),
        paths.target_reading(),
        paths.blob(&host.sha),
        paths.blobs().join(format!(".{}.4242.partial", host.sha)),
        store_path(paths, XRAY, &host.sha),
        paths.txn_lock(),
        paths.gate_lock(),
    ] {
        put(&file);
    }
    fs::create_dir_all(paths.validate_dir()).unwrap();
    assert_eq!(
        revert_pending(paths, &host.node(), Why::Rebooted),
        Err(AgentError::NotAwaitingConfirm)
    );
    assert_eq!(prior_state(paths), Ok(None));
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()));
}

/// The agent's own digest is checked first: an agent that is not the one
/// expected says so, on a host that ran Mooring before too.
#[test]
fn bootstrap_checks_its_own_digest_before_the_host() {
    let host = Host::new();
    leave(&host.paths, PriorState::Usage);
    let node = host.node();
    let expected = Sha256Hex::from_bytes([7; 32]);
    assert_eq!(
        ask(
            &host.paths,
            &node,
            Role::Bootstrap,
            frame(&request(expected))
        ),
        Err(AgentError::AgentShaMismatch {
            expected,
            actual: host.sha,
        })
    );
    assert!(node.calls().is_empty());
}

/// Each location the error names is where the agent keeps that state, and
/// the directories among them are the profile's.
#[test]
fn each_location_is_where_the_agent_keeps_the_state() {
    let (_dir, paths) = crate::tests::scratch();
    for &state in PriorState::ALL {
        let kept = match state {
            PriorState::Generations => paths.etc(),
            PriorState::Transactions => paths.txn_dir(),
            PriorState::Usage => paths.usage_dir(),
            PriorState::Halted => paths.halted(),
            PriorState::Holds => paths.gate_dir(),
            PriorState::StopRequest => paths.stop_dir(),
            PriorState::MacReport => paths.mac_report(),
        };
        assert_eq!(paths.at(state.path()), kept, "{state:?}");
        assert_eq!(
            state.is_directory(),
            HostProfile::CURRENT
                .directories
                .iter()
                .any(|dir| dir.path == state.path()),
            "{state:?}"
        );
    }
}

/// Names are judged whatever their encoding. APFS refuses such names, so
/// this runs on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn names_that_are_not_utf8_count() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let bootstrapped = bootstrapped();
    for name in [&b"\xff.json"[..], b".\xff.json.4242.tmp"] {
        let host = bootstrapped.copy();
        put(&host.paths.usage_dir().join(OsStr::from_bytes(name)));
        assert_refused(&host, PriorState::Usage, &String::from_utf8_lossy(name));
    }
}
