// SPDX-License-Identifier: GPL-3.0-or-later

//! The profile's accounts as `/etc/passwd` and `/etc/group` say: a
//! database that cannot be read, or holds a line of another shape, is an
//! error, never an account that is missing; and an account the tools do
//! not correct stops `Bootstrap` at its step.

use std::fs;

use mooring_agent_proto::{AgentError, BootstrapStep, HostAccount, IoOp, StderrTail};

use super::{ENOENT, FakeNode, bootstrapped, failed, ok, own_ids, scratch};
use crate::accounts;
use crate::host::Tool;
use crate::store::malformed;

#[test]
fn a_database_that_cannot_be_read_is_an_error() {
    let (_dir, paths) = scratch();
    let missing = AgentError::Io {
        op: IoOp::ReadState,
        errno: Some(ENOENT),
    };
    assert_eq!(accounts::user(&paths, "root"), Err(missing.clone()));
    assert_eq!(accounts::group_id(&paths, "root"), Err(missing));
}

#[test]
fn a_line_of_another_shape_is_refused_not_skipped() {
    let (_dir, paths) = scratch();
    let (uid, gid) = own_ids(&paths);
    fs::create_dir_all(paths.at("/etc")).unwrap();
    fs::write(
        paths.passwd(),
        format!("root:x:{uid}:{gid}:root:/root\nmooring-view:x:many:{gid}::/nonexistent:/bin/sh\n"),
    )
    .unwrap();
    fs::write(paths.group(), format!("root:x:{gid}\nmooring:x:lots:\n")).unwrap();
    for name in ["root", "mooring-view"] {
        assert_eq!(
            accounts::user(&paths, name),
            Err(malformed(IoOp::ReadState)),
            "{name}"
        );
    }
    for name in ["root", "mooring"] {
        assert_eq!(
            accounts::group_id(&paths, name),
            Err(malformed(IoOp::ReadState)),
            "{name}"
        );
    }
}

#[test]
fn an_owner_the_host_lacks_is_its_account_missing_or_a_damaged_database() {
    let (_dir, paths) = scratch();
    bootstrapped(&paths);
    let (uid, gid) = own_ids(&paths);
    fs::write(
        paths.passwd(),
        format!("root:x:{uid}:{gid}:root:/root:/bin/bash\n"),
    )
    .unwrap();
    assert_eq!(
        accounts::ids(&paths, HostAccount::Watch.name(), "mooring"),
        Err(AgentError::AccountMissing {
            account: HostAccount::Watch
        })
    );
    fs::write(paths.passwd(), "").unwrap();
    assert_eq!(
        accounts::ids(&paths, "root", "root"),
        Err(malformed(IoOp::ReadState)),
        "a host without root"
    );
}

#[test]
fn an_account_usermod_cannot_correct_stops_bootstrap_at_its_step() {
    let (_dir, paths) = scratch();
    bootstrapped(&paths);
    let passwd = fs::read_to_string(paths.passwd())
        .unwrap()
        .replace("/nonexistent:/bin/sh\n", "/nonexistent:/usr/sbin/nologin\n");
    fs::write(paths.passwd(), passwd).unwrap();
    let node = FakeNode::answering(
        0,
        Box::new(|tool, _| {
            Ok(match tool {
                Tool::Usermod => failed(b"usermod: cannot lock /etc/passwd; try again later.\n"),
                _ => ok(b""),
            })
        }),
    );
    assert_eq!(
        accounts::converge(&paths, &node),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::Accounts,
            stderr_tail: StderrTail::scrubbed(
                b"usermod: cannot lock /etc/passwd; try again later.\n",
                &[]
            ),
        })
    );
    assert_eq!(
        node.calls(),
        ["/usr/sbin/usermod --gid mooring --home /nonexistent --shell /bin/sh mooring-view"]
    );
}
