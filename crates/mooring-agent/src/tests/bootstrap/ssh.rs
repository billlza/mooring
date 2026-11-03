// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's SSH steps (design §13.2): root's `authorized_keys`, the
//! injected host key replaced by a fresh one (the fresh key an earlier
//! attempt left removed first, and every other host key judged by its
//! name's bytes), sshd's reload, and the record of the new key. A failure
//! stops bootstrap: keys that cannot be written stop it before the host
//! key; a host key that cannot be made leaves the old one and sshd as
//! they were, with the keys restricted; a stale key that cannot be
//! removed stops it before a new one is made; an sshd that will not
//! reload leaves the new key unrecorded; and a host key that cannot be
//! read back is refused. After a host key that cannot be made, and after
//! an sshd that will not reload, a retry goes through.

use std::fs;

use mooring_agent_proto::{AgentError, BootstrapStep, IoOp, Role, SshEd25519Key, StderrTail};

use super::world::{Host, NEW_HOST_KEY, new_key, write};
use crate::store::{malformed, read_json};
use crate::tests::{EEXIST, EISDIR};

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
    // What unlinking a directory gives on this OS: EPERM on macOS, EISDIR
    // on Linux.
    let probe = host.paths.at("/probe");
    fs::create_dir(&probe).unwrap();
    let errno = fs::remove_file(&probe).unwrap_err().raw_os_error();
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
