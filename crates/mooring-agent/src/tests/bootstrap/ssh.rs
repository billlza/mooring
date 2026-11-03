// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's SSH steps (design §13.2): root's `authorized_keys`, the
//! injected host key replaced by a fresh one (the fresh key an earlier
//! attempt left removed first, and every other host key judged by its
//! name's bytes), sshd's reload, and the record of the new key. A failure
//! stops bootstrap: keys that cannot be written stop it before the host
//! key; a host key that cannot be made, by a tool that fails or
//! cannot start, leaves the old one and sshd as they were, with the keys
//! restricted, and so does a new key with a half missing (the public half
//! goes first, so the private key, which sshd serves, stays the old one
//! until both are in place); a stale key that cannot be removed stops it
//! before a new one is made; host keys that cannot be listed, or another
//! that cannot be removed, stop it with the new key in place and sshd not
//! reloaded; an sshd that will not reload, and a new key that cannot be
//! recorded, leave the new key unrecorded; and a host key that cannot be
//! read back is refused. Once the fault is gone, a retry after a key that
//! could not be made or put in place, keys that could not be listed, an
//! sshd that would not reload or a key that could not be recorded goes
//! through and makes a new key.

use std::fs;

use mooring_agent_proto::{AgentError, BootstrapStep, IoOp, Role, SshEd25519Key, StderrTail};

use super::world::{Host, INJECTED_HOST_KEY, KeyHalf, NEW_HOST_KEY, new_key, write};
use crate::host::Tool;
use crate::store::{malformed, read_json};
use crate::tests::{EACCES, EEXIST, EISDIR, ENOENT, ModeFault, occupy_temporary};

/// What unlinking a directory gives on this OS: `EPERM` on macOS, `EISDIR`
/// on Linux.
fn unlinking_a_directory(host: &Host) -> Option<i32> {
    let probe = host.paths.at("/probe");
    fs::create_dir(&probe).unwrap();
    let errno = fs::remove_file(&probe).unwrap_err().raw_os_error();
    fs::remove_dir(&probe).unwrap();
    errno
}

/// Whether the node was asked to reload sshd.
fn reloaded(calls: &[String]) -> bool {
    calls
        .iter()
        .any(|call| call == "/usr/bin/systemctl reload ssh.service")
}

/// The host key whole as the user-data injected it.
fn assert_old_host_key(host: &Host) {
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "injected private"
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_dir().join("ssh_host_ed25519_key.pub")).unwrap(),
        format!("{INJECTED_HOST_KEY} root@cloud\n")
    );
}

/// No key recorded, so that a retry makes one anew.
fn assert_unrecorded(host: &Host) {
    assert_eq!(
        read_json::<SshEd25519Key>(&host.paths.host_key_record()),
        Ok(None)
    );
}

#[test]
fn a_host_key_failure_leaves_the_keys_restricted_and_sshd_as_it_was() {
    let host = Host::new();
    host.faults.borrow_mut().keygen_fails = true;
    let node = host.node();
    assert!(matches!(
        host.bootstrap(&node),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::HostKey,
            ..
        })
    ));
    // The bootstrap key can run the forced command again: a retry works.
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    assert!(keys.starts_with(Role::Bootstrap.authorized_keys_options()));
    assert!(host.paths.agent_current().exists());
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "injected private"
    );
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("reload ssh.service"))
    );
    assert_eq!(
        read_json::<SshEd25519Key>(&host.paths.host_key_record()),
        Ok(None)
    );
    // The retry replaces the key.
    host.faults.borrow_mut().keygen_fails = false;
    assert_eq!(
        host.bootstrap(&host.node()),
        Ok(SshEd25519Key::new(NEW_HOST_KEY).unwrap())
    );
}

#[test]
fn keys_that_cannot_be_written_stop_bootstrap_before_the_host_key() {
    let host = Host::new();
    // A file stands where root's `.ssh` directory belongs.
    fs::remove_dir_all(host.paths.at("/root/.ssh")).unwrap();
    write(&host.paths, "/root/.ssh", "not a directory");
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("ssh-keygen") && !call.contains("reload ssh.service")),
        "{:#?}",
        node.calls()
    );
}

#[test]
fn an_sshd_that_will_not_reload_leaves_the_new_key_unrecorded_for_a_retry() {
    let host = Host::new();
    host.faults.borrow_mut().reload_fails = true;
    assert_eq!(
        host.bootstrap(&host.node()),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::SshdReload,
            stderr_tail: StderrTail::scrubbed(b"Job for ssh.service failed.\n", &[]),
        })
    );
    assert_eq!(
        read_json::<SshEd25519Key>(&host.paths.host_key_record()),
        Ok(None)
    );
    host.faults.borrow_mut().reload_fails = false;
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()));
    assert_eq!(
        read_json(&host.paths.host_key_record()),
        Ok(Some(new_key()))
    );
}

#[test]
fn a_fresh_key_an_earlier_attempt_left_is_removed_before_the_new_one_is_made() {
    let host = Host::new();
    write(
        &host.paths,
        "/etc/ssh/ssh_host_ed25519_key.mooring",
        "stale private",
    );
    write(
        &host.paths,
        "/etc/ssh/ssh_host_ed25519_key.mooring.pub",
        "stale public\n",
    );
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()));
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
    assert!(
        !host
            .paths
            .ssh_dir()
            .join("ssh_host_ed25519_key.mooring")
            .exists()
    );
}

#[test]
fn a_stale_key_that_cannot_be_removed_stops_bootstrap_with_the_old_key() {
    let host = Host::new();
    fs::create_dir(host.paths.ssh_dir().join("ssh_host_ed25519_key.mooring")).unwrap();
    let errno = unlinking_a_directory(&host);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno
        })
    );
    assert!(node.calls().iter().all(|call| !call.contains("ssh-keygen")));
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "injected private"
    );
}

#[test]
fn a_host_key_that_cannot_be_read_back_is_refused() {
    let host = Host::new();
    host.bootstrap(&host.node()).unwrap();
    let public = host.paths.ssh_dir().join("ssh_host_ed25519_key.pub");
    for damaged in ["ssh-ed25519\n", "ssh-ed25519 AAAA root@node\n"] {
        fs::write(&public, damaged).unwrap();
        assert_eq!(
            host.bootstrap(&host.node()),
            Err(malformed(IoOp::ReadState)),
            "{damaged:?}"
        );
    }
    fs::remove_file(&public).unwrap();
    fs::create_dir(&public).unwrap();
    assert_eq!(
        host.bootstrap(&host.node()),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(EISDIR)
        })
    );
}

/// A host key tool that cannot be started leaves the old key and sshd as
/// they were, with the keys restricted; a retry goes through.
#[test]
fn a_host_key_tool_that_cannot_start_leaves_the_old_key() {
    let host = Host::new();
    host.faults.borrow_mut().unstartable = Some(Tool::SshKeygen);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::SpawnProcess,
            errno: Some(ENOENT)
        })
    );
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    assert!(keys.starts_with(Role::Bootstrap.authorized_keys_options()));
    assert_old_host_key(&host);
    assert!(!reloaded(&node.calls()));
    assert_unrecorded(&host);
    host.faults.borrow_mut().unstartable = None;
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
}

/// A new key without its public half (`ssh-keygen` wrote the private one
/// only) is not put in place: the old key stays whole, sshd is not
/// reloaded, and a retry removes the half left and goes through.
#[test]
fn a_new_key_without_its_public_half_leaves_the_old_key_for_a_retry() {
    let host = Host::new();
    host.faults.borrow_mut().keygen_writes_only = Some(KeyHalf::Private);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOENT)
        })
    );
    assert_old_host_key(&host);
    let fresh = host.paths.ssh_dir().join("ssh_host_ed25519_key.mooring");
    assert_eq!(fs::read_to_string(&fresh).unwrap(), "fresh private", "left");
    assert!(!reloaded(&node.calls()));
    assert_unrecorded(&host);
    host.faults.borrow_mut().keygen_writes_only = None;
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
    assert!(!fresh.exists());
}

/// A new key without its private half: its public half is renamed over
/// the old one first, and the private key, which sshd serves, stays the
/// old one, with sshd not reloaded; a retry puts a whole key in place.
#[test]
fn a_new_key_without_its_private_half_leaves_sshd_the_old_private_key() {
    let host = Host::new();
    host.faults.borrow_mut().keygen_writes_only = Some(KeyHalf::Public);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOENT)
        })
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "injected private"
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_dir().join("ssh_host_ed25519_key.pub")).unwrap(),
        format!("{NEW_HOST_KEY} \n")
    );
    assert!(!reloaded(&node.calls()));
    assert_unrecorded(&host);
    host.faults.borrow_mut().keygen_writes_only = None;
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
}

/// Host keys that cannot be listed (sshd's directory may be written and
/// searched, not read) stop bootstrap with the new key in place, the
/// others left and sshd not reloaded; a retry makes a key anew and
/// removes the others.
#[test]
fn host_keys_that_cannot_be_listed_stop_bootstrap_before_sshd_is_reloaded() {
    let host = Host::new();
    let unreadable = ModeFault::set(&host.paths.ssh_dir(), 0o300);
    let node = host.node();
    let outcome = host.bootstrap(&node);
    drop(unreadable);
    assert_eq!(
        outcome,
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EACCES)
        })
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
    let rsa = host.paths.ssh_dir().join("ssh_host_rsa_key");
    assert!(rsa.exists(), "the other keys left");
    assert!(!reloaded(&node.calls()));
    assert_unrecorded(&host);
    let retry = host.node();
    assert_eq!(host.bootstrap(&retry), Ok(new_key()), "a retry");
    assert!(
        retry
            .calls()
            .iter()
            .any(|call| call.starts_with("/usr/bin/ssh-keygen ")),
        "a key made anew"
    );
    assert!(!rsa.exists());
}

/// Another host key that cannot be removed (a directory under its name)
/// stops bootstrap with the new key in place and sshd not reloaded.
#[test]
fn another_host_key_that_cannot_be_removed_stops_bootstrap_before_sshd_is_reloaded() {
    let host = Host::new();
    let rsa = host.paths.ssh_dir().join("ssh_host_rsa_key");
    fs::remove_file(&rsa).unwrap();
    fs::remove_file(host.paths.ssh_dir().join("ssh_host_rsa_key.pub")).unwrap();
    fs::create_dir(&rsa).unwrap();
    let errno = unlinking_a_directory(&host);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno
        })
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
    assert!(rsa.is_dir());
    assert!(!reloaded(&node.calls()));
    assert_unrecorded(&host);
}

/// A new key that cannot be recorded leaves it in place and sshd
/// reloaded, but unrecorded: a retry makes a key anew and records it.
#[test]
fn a_new_key_that_cannot_be_recorded_is_made_anew_by_a_retry() {
    let host = Host::new();
    let blocker = occupy_temporary(&host.paths.host_key_record());
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
    assert_eq!(
        node.calls().last().unwrap(),
        "/usr/bin/systemctl reload ssh.service"
    );
    assert_unrecorded(&host);
    fs::remove_dir(&blocker).unwrap();
    let retry = host.node();
    assert_eq!(host.bootstrap(&retry), Ok(new_key()), "a retry");
    assert!(
        retry
            .calls()
            .iter()
            .any(|call| call.starts_with("/usr/bin/ssh-keygen ")),
        "a key made anew"
    );
    assert_eq!(
        read_json(&host.paths.host_key_record()),
        Ok(Some(new_key()))
    );
}

/// Host keys are judged by their names' bytes: one whose name is not UTF-8
/// goes like any other key the profile does not keep, and a file that is
/// no host key stays. APFS refuses such names, so this runs on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn a_host_key_whose_name_is_not_utf8_goes_like_any_other() {
    use std::os::unix::ffi::OsStrExt;
    let host = Host::new();
    let odd = host
        .paths
        .ssh_dir()
        .join(std::ffi::OsStr::from_bytes(b"ssh_host_\xff_key"));
    let other = host
        .paths
        .ssh_dir()
        .join(std::ffi::OsStr::from_bytes(b"\xffmoduli"));
    fs::write(&odd, "a key the profile does not keep").unwrap();
    fs::write(&other, "no host key").unwrap();
    assert_eq!(
        host.bootstrap(&host.node()),
        Ok(SshEd25519Key::new(NEW_HOST_KEY).unwrap())
    );
    assert!(!odd.exists());
    assert!(other.exists());
}
