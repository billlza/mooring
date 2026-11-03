// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's accounts (design §13.2) on the stand-in host: an account
//! that differs from the profile, a viewer without a real shell included,
//! is corrected with `usermod`; an account tool that fails (a group's
//! included), or an account the tools did not correct, stops bootstrap at
//! its step before anything after the accounts, as do an account or a
//! group the tools did not add, which is the account missing, an account
//! tool that cannot start and an account database that cannot be read.
//! `accounts::converge` and the account databases on their own are tested
//! in `tests::accounts`.

use std::fs;

use mooring_agent_proto::{AgentError, BootstrapStep, HostAccount, IoOp, StderrTail};

use super::world::{Failing, Host, write};
use crate::host::Tool;
use crate::tests::{EISDIR, ENOENT, own_ids};

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

/// A group `groupadd` cannot add stops bootstrap at its step, with what
/// it printed, before any account is added.
#[test]
fn a_group_that_cannot_be_added_stops_bootstrap_at_its_step() {
    const LOCKED: &str = "groupadd: cannot lock /etc/group; try again later.\n";
    let host = Host::new();
    host.faults.borrow_mut().failing = Some(Failing {
        tool: Tool::Groupadd,
        argument: "mooring",
        stderr: LOCKED,
    });
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::Accounts,
            stderr_tail: StderrTail::scrubbed(LOCKED.as_bytes(), &[]),
        })
    );
    let calls = node.calls();
    assert_eq!(calls.len(), 2, "dpkg-query, then groupadd: {calls:#?}");
    assert_eq!(calls[1], "/usr/sbin/groupadd --system mooring");
    assert_eq!(crate::accounts::group_id(&host.paths, "mooring"), Ok(None));
    assert!(!host.paths.var_lib().exists(), "nothing after the accounts");
}

/// An account tool that cannot be started stops bootstrap at once.
#[test]
fn an_account_tool_that_cannot_start_stops_bootstrap_at_once() {
    let host = Host::new();
    host.faults.borrow_mut().unstartable = Some(Tool::Useradd);
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::SpawnProcess,
            errno: Some(ENOENT)
        })
    );
    assert_eq!(
        node.calls().last().unwrap(),
        "/usr/sbin/useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid mooring mooring-watch"
    );
    assert_eq!(
        crate::accounts::user(&host.paths, HostAccount::Watch.name()),
        Ok(None)
    );
    assert!(!host.paths.var_lib().exists(), "nothing after the accounts");
}

/// An account, or its group, that a tool said it added but the databases
/// do not hold is the account missing, never assumed made.
#[test]
fn an_account_or_group_the_tools_did_not_add_is_missing() {
    for tool in [Tool::Useradd, Tool::Groupadd] {
        let host = Host::new();
        host.faults.borrow_mut().ignored = Some(tool);
        assert_eq!(
            host.bootstrap(&host.node()),
            Err(AgentError::AccountMissing {
                account: HostAccount::Watch
            }),
            "{tool:?}"
        );
        assert!(!host.paths.var_lib().exists(), "nothing after the accounts");
    }
}

/// An account database that cannot be read stops bootstrap at the
/// accounts, as the read that failed.
#[test]
fn a_database_that_cannot_be_read_stops_bootstrap_at_the_accounts() {
    for database in ["/etc/group", "/etc/passwd"] {
        let host = Host::new();
        let path = host.paths.at(database);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            host.bootstrap(&host.node()),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: Some(EISDIR)
            }),
            "{database}"
        );
        assert!(!host.paths.var_lib().exists(), "nothing after the accounts");
    }
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
    host.faults.borrow_mut().ignored = Some(Tool::Usermod);
    let node = host.node();
    let Err(AgentError::Bootstrap { step, stderr_tail }) = host.bootstrap(&node) else {
        panic!("not a bootstrap failure");
    };
    assert_eq!(step, BootstrapStep::Accounts);
    assert!(stderr_tail.as_str().contains("mooring-view still differs"));
    assert!(!host.paths.etc().exists(), "nothing after the accounts");
}
