// SPDX-License-Identifier: GPL-3.0-or-later

//! The accounts and directories of the host profile through a transaction
//! (design §8.6): a node bootstrapped at an older profile, or with none
//! recorded, takes those this agent's profile adds before anything is
//! staged, as profile 3's target check account comes to a node
//! bootstrapped at 2; a node at this profile runs no account tool and
//! keeps its directories as they are; and an account that cannot be made
//! fails the change with nothing staged or switched.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use mooring_agent_proto::{
    AgentError, HostAccount, HostProfile, HostProfileVersion, SETGID, StderrTail, TxnState,
};

use super::world::{World, assert_unswitched, idle, index_of, same};
use crate::store::{read_json, write_json};

/// The target check's account and its directory, as host profile 3 adds
/// them.
const ACCOUNT: &str = "mooring-target-check";
const DIRECTORY: &str = "/var/lib/mooring/target";

/// `useradd` for the target check's account, as the profile defines it.
const USERADD: &str = "/usr/sbin/useradd --system --no-create-home --home-dir /nonexistent \
                       --shell /usr/sbin/nologin --gid mooring mooring-target-check";

/// A node with generation 1 committed, as one bootstrapped at host
/// profile 2 is: no target check account and no directory for it, and
/// version 2 recorded (`recorded`, or no record at all).
fn bootstrapped_at_2(recorded: bool) -> World {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let passwd = fs::read_to_string(world.paths.passwd()).unwrap();
    let kept: String = passwd
        .lines()
        .filter(|line| !line.starts_with(&format!("{ACCOUNT}:")))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(kept, passwd);
    fs::write(world.paths.passwd(), kept).unwrap();
    let _absent = fs::remove_dir_all(world.paths.at(DIRECTORY));
    if recorded {
        write_json(
            &world.paths.host_profile(),
            &HostProfileVersion::new(2),
            0o640,
        )
        .unwrap();
    } else {
        fs::remove_file(world.paths.host_profile()).unwrap();
    }
    world
}

fn mode(world: &World, path: &str) -> u32 {
    fs::metadata(world.paths.at(path))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn a_node_at_an_older_profile_takes_this_ones_accounts_and_directories_first() {
    for recorded in [true, false] {
        let world = bootstrapped_at_2(recorded);
        let node = world.node(2000);
        assert_eq!(
            world.apply_and_run(&node, world.bundle(2, idle(301))),
            TxnState::AwaitingConfirm,
            "recorded: {recorded}"
        );
        let calls = node.calls();
        // Made before anything was staged: its group was there, so only
        // the account, with the profile's home, shell and group.
        let made = index_of(&calls, USERADD);
        assert!(made < index_of(&calls, "/usr/bin/systemd-analyze verify"));
        assert!(
            calls
                .iter()
                .all(|call| !call.contains("groupadd") && !call.contains("usermod")),
            "{calls:#?}"
        );
        let user = crate::accounts::user(&world.paths, ACCOUNT)
            .unwrap()
            .unwrap();
        assert_eq!(
            (user.home.as_str(), user.shell.as_str()),
            (
                HostAccount::TargetCheck.home(),
                HostAccount::TargetCheck.shell()
            )
        );
        // Its directory, with the layout's mode, and every other one kept
        // as the layout sets it.
        assert_eq!(mode(&world, DIRECTORY), SETGID | 0o750);
        for dir in HostProfile::CURRENT.directories {
            assert_eq!(mode(&world, dir.path), dir.mode, "{}", dir.path);
        }
        // The swap recorded this profile, so the next change finds the
        // accounts in place and runs no account tool.
        assert_eq!(
            read_json(&world.paths.host_profile()).unwrap(),
            Some(HostProfile::CURRENT.version)
        );
        assert_eq!(
            crate::txn::confirm(&world.paths, &node, mooring_agent_proto::Generation::new(2)),
            Ok(mooring_agent_proto::Generation::new(2))
        );
        let next = world.node(3000);
        assert_eq!(
            world.apply_and_run(&next, world.bundle(3, idle(302))),
            TxnState::AwaitingConfirm
        );
        assert!(next.calls().iter().all(|call| !call.contains("useradd")));
    }
}

/// A node at this agent's profile has its accounts and directories from
/// `Bootstrap` or the transaction that installed the profile: a change
/// neither runs an account tool nor touches a directory, even one whose
/// mode was changed since.
#[test]
fn a_node_at_this_profile_runs_no_account_tool_and_keeps_its_directories() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    fs::create_dir_all(world.paths.at(DIRECTORY)).unwrap();
    fs::set_permissions(world.paths.at(DIRECTORY), fs::Permissions::from_mode(0o700)).unwrap();
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, idle(301))),
        TxnState::AwaitingConfirm
    );
    for tool in ["groupadd", "useradd", "usermod"] {
        assert!(
            node.calls().iter().all(|call| !call.contains(tool)),
            "{tool}"
        );
    }
    assert_eq!(mode(&world, DIRECTORY), 0o700);
}

#[test]
fn an_account_that_cannot_be_made_fails_the_change_before_staging() {
    let world = bootstrapped_at_2(true);
    world.faults.borrow_mut().useradd_fails = true;
    let node = world.node(2000);
    world.apply_and_run(&node, world.bundle(2, idle(301)));
    assert_unswitched(
        &world,
        2,
        Some("gen-1"),
        AgentError::Accounts {
            stderr_tail: StderrTail::scrubbed(
                b"useradd: cannot lock /etc/passwd; try again later.\n",
                &[],
            ),
        },
    );
    let calls = node.calls();
    index_of(&calls, USERADD);
    assert!(
        calls.iter().all(|call| !call.contains("systemd-analyze")),
        "nothing was staged or validated: {calls:#?}"
    );
    // The older profile stays recorded, so the next change tries again.
    assert_eq!(
        read_json(&world.paths.host_profile()).unwrap(),
        Some(HostProfileVersion::new(2))
    );
}
