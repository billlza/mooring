// SPDX-License-Identifier: GPL-3.0-or-later

//! `Bootstrap` and `RevokeBootstrap` where a step fails: a tool that cannot
//! start or refuses, a file that cannot be written or read back. Each is
//! reported as its step or as the I/O failure it is, before anything that
//! would lock the Mac out, so that a retry goes through.

use std::fs;

use mooring_agent_proto::{
    AgentError, BootstrapStep, HostProfile, IoOp, Role, SshEd25519Key, StderrTail,
};

use super::{BOOTSTRAP_KEY, Host, NEW_HOST_KEY, OPS_KEY, write};
use crate::bootstrap::revoke;
use crate::store::{malformed, read_json};
use crate::tests::{EEXIST, EISDIR, ENOENT, ENOTDIR, bootstrapped, occupy_temporary};

fn new_key() -> SshEd25519Key {
    SshEd25519Key::new(NEW_HOST_KEY).unwrap()
}

#[test]
fn a_package_tool_that_cannot_start_stops_bootstrap_at_once() {
    let spawn = AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: Some(ENOENT),
    };
    let host = Host::new();
    host.faults.borrow_mut().dpkg_unstartable = true;
    let node = host.node();
    assert_eq!(host.bootstrap(&node), Err(spawn.clone()));
    assert_eq!(node.calls().len(), 1);
    let host = Host::new();
    {
        let mut faults = host.faults.borrow_mut();
        faults.missing_packages = true;
        faults.apt_unstartable = true;
    }
    let node = host.node();
    assert_eq!(host.bootstrap(&node), Err(spawn));
    assert_eq!(node.calls().len(), 2, "dpkg-query, then apt-get update");
    assert!(!host.paths.var_lib().exists());
}

#[test]
fn an_agent_link_that_cannot_be_made_stops_bootstrap_before_the_keys() {
    let host = Host::new();
    // The link's temporary name is taken.
    let link = host.paths.agent_current();
    let blocker = link.with_extension(format!("swap.{}", std::process::id()));
    fs::create_dir_all(&blocker).unwrap();
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    assert_eq!(
        host.bootstrap(&host.node()),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert!(fs::symlink_metadata(&link).is_err(), "no link");
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        keys,
        "the keys as the user-data left them"
    );
    fs::remove_dir(&blocker).unwrap();
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
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

#[test]
fn a_layout_directory_under_a_file_is_a_state_write() {
    let host = Host::new();
    bootstrapped(&host.paths);
    // A file stands where `/var/lib` belongs.
    fs::remove_dir_all(host.paths.at("/var/lib")).unwrap();
    write(&host.paths, "/var/lib", "not a directory");
    assert_eq!(
        crate::layout::converge(&host.paths, &HostProfile::CURRENT),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOTDIR)
        })
    );
}

#[test]
fn revoke_reports_keys_it_cannot_rewrite_or_read() {
    let host = Host::new();
    let keys = host.paths.root_authorized_keys();
    let both = format!(
        "{} {BOOTSTRAP_KEY}\n{} {OPS_KEY}\n",
        Role::Bootstrap.authorized_keys_options(),
        Role::Ops.authorized_keys_options()
    );
    fs::write(&keys, &both).unwrap();
    let blocker = occupy_temporary(&keys);
    assert_eq!(
        revoke(&host.paths),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert_eq!(fs::read_to_string(&keys).unwrap(), both, "both lines kept");
    fs::remove_dir(&blocker).unwrap();
    fs::remove_file(&keys).unwrap();
    fs::create_dir(&keys).unwrap();
    assert_eq!(
        revoke(&host.paths),
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
