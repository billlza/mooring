// SPDX-License-Identifier: GPL-3.0-or-later

//! `RevokeBootstrap` (design §13.2): it removes the bootstrap role's line
//! from root's `authorized_keys` and nothing else, and has nothing to do
//! when no such line, or no keys file, is left. Keys it cannot rewrite are
//! reported with both lines kept; keys it cannot read, as the read that
//! failed.

use std::fs;

use mooring_agent_proto::{AgentError, IoOp, Role};

use super::world::{BOOTSTRAP_KEY, Host, OPS_KEY, mode};
use crate::bootstrap::revoke;
use crate::tests::{EEXIST, EISDIR, occupy_temporary, scratch};

#[test]
fn revoke_removes_only_the_bootstrap_line() {
    let host = Host::new();
    host.bootstrap(&host.node()).unwrap();
    revoke(&host.paths).unwrap();
    let ops_only = format!("{} {OPS_KEY}\n", Role::Ops.authorized_keys_options());
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        ops_only
    );
    assert_eq!(mode(&host.paths.root_authorized_keys()), 0o600);
    // Again: nothing to remove.
    revoke(&host.paths).unwrap();
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        ops_only
    );
}

#[test]
fn revoke_with_no_keys_file_has_nothing_to_do() {
    let (_dir, paths) = scratch();
    assert_eq!(revoke(&paths), Ok(()));
    assert!(!paths.root_authorized_keys().exists());
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
