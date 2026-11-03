// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's accounts (design §13.2) on the stand-in host: an account
//! that differs from the profile, a viewer without a real shell included,
//! is corrected with `usermod`; an account tool that fails, or an account
//! the tools did not correct, stops bootstrap at its step before anything
//! after the accounts. `accounts::converge` and the account databases on
//! their own are tested in `tests::accounts`.

use mooring_agent_proto::{AgentError, BootstrapStep};

use super::world::{Host, write};
use crate::tests::own_ids;

#[test]
fn an_account_that_differs_from_the_profile_is_corrected() {
    let host = Host::new();
    let (uid, gid) = own_ids(&host.paths);
    write(
        &host.paths,
        "/etc/passwd",
        &format!(
            "root:x:{uid}:{gid}:root:/root:/bin/bash\n\
             mooring-view:x:{uid}:{gid}::/home/view:/usr/sbin/nologin\n"
        ),
    );
    write(
        &host.paths,
        "/etc/group",
        &format!("root:x:{gid}:\nmooring:x:{gid}:\n"),
    );
    let node = host.node();
    host.bootstrap(&node).unwrap();
    assert!(
        node.calls().contains(
            &"/usr/sbin/usermod --gid mooring --home /nonexistent --shell /bin/sh mooring-view"
                .to_owned()
        )
    );
    let view = crate::accounts::user(&host.paths, "mooring-view")
        .unwrap()
        .unwrap();
    assert_eq!(view.shell, "/bin/sh");
}

#[test]
fn an_account_tool_failure_stops_bootstrap_with_its_step() {
    let host = Host::new();
    host.faults.borrow_mut().useradd_fails = true;
    let node = host.node();
    let Err(AgentError::Bootstrap { step, stderr_tail }) = host.bootstrap(&node) else {
        panic!("not a bootstrap failure");
    };
    assert_eq!(step, BootstrapStep::Accounts);
    assert!(stderr_tail.as_str().contains("cannot lock"));
    assert!(!host.paths.etc().exists());
}

/// Writes a viewer that differs from the profile only in `shell`.
fn viewer_with_shell(host: &Host, shell: &str) {
    let (uid, gid) = own_ids(&host.paths);
    write(
        &host.paths,
        "/etc/passwd",
        &format!(
            "root:x:{uid}:{gid}:root:/root:/bin/bash\n\
             mooring-view:x:{uid}:{gid}::/nonexistent:{shell}\n"
        ),
    );
    write(
        &host.paths,
        "/etc/group",
        &format!("root:x:{gid}:\nmooring:x:{gid}:\n"),
    );
}

#[test]
fn a_viewer_without_a_real_shell_is_given_one() {
    let host = Host::new();
    viewer_with_shell(&host, "/usr/sbin/nologin");
    let node = host.node();
    host.bootstrap(&node).unwrap();
    assert!(
        node.calls().contains(
            &"/usr/sbin/usermod --gid mooring --home /nonexistent --shell /bin/sh mooring-view"
                .to_owned()
        )
    );
}

#[test]
fn an_account_the_tools_did_not_correct_is_reported() {
    let host = Host::new();
    viewer_with_shell(&host, "/usr/sbin/nologin");
    host.faults.borrow_mut().usermod_ignored = true;
    let node = host.node();
    let Err(AgentError::Bootstrap { step, stderr_tail }) = host.bootstrap(&node) else {
        panic!("not a bootstrap failure");
    };
    assert_eq!(step, BootstrapStep::Accounts);
    assert!(stderr_tail.as_str().contains("mooring-view still differs"));
    assert!(!host.paths.etc().exists(), "nothing after the accounts");
}
