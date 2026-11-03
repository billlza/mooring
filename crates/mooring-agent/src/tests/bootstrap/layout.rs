// SPDX-License-Identifier: GPL-3.0-or-later

//! The agent's directories (design §8.6), which bootstrap lays out after
//! the accounts: each gets its group; a link where a directory belongs is
//! refused rather than followed; a directory under a file is a state write
//! that fails; and a missing state group is the watch's missing account.
//! The paths the agent and the watch write are checked here too, against
//! the profile's directories and the ones the watch's unit lets it write.

use std::fs;

use mooring_agent_proto::{AgentError, HostAccount, HostProfile, IoOp};

use super::world::{Host, write};
use crate::tests::{ENOTDIR, bootstrapped, own_ids, scratch};

#[test]
fn the_layout_refuses_a_link_where_a_directory_belongs() {
    let host = Host::new();
    bootstrapped(&host.paths);
    fs::create_dir_all(host.paths.var_lib()).unwrap();
    std::os::unix::fs::symlink("/tmp", host.paths.gate_dir()).unwrap();
    assert_eq!(
        crate::layout::converge(&host.paths, &HostProfile::CURRENT),
        Err(crate::store::malformed(IoOp::WriteState))
    );
}

#[test]
fn a_missing_state_group_is_the_watchs_missing_account() {
    let host = Host::new();
    bootstrapped(&host.paths);
    let (_, gid) = own_ids(&host.paths);
    write(
        &host.paths,
        "/etc/group",
        &format!("root:x:{gid}:\nmooring-xray:x:{gid}:\nmooring-hy2:x:{gid}:\n"),
    );
    assert_eq!(
        crate::layout::converge(&host.paths, &HostProfile::CURRENT),
        Err(AgentError::AccountMissing {
            account: HostAccount::Watch
        })
    );
}

#[test]
fn the_layout_gives_each_directory_its_group() {
    use std::os::unix::fs::MetadataExt;
    let host = Host::new();
    bootstrapped(&host.paths);
    let (_, primary) = own_ids(&host.paths);
    let output = std::process::Command::new("id").arg("-G").output().unwrap();
    let other: u32 = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|gid| gid.parse().unwrap())
        .find(|gid| *gid != primary)
        .expect("this test needs a user in a group besides its own");
    write(
        &host.paths,
        "/etc/group",
        &format!(
            "root:x:{primary}:\nmooring:x:{other}:\nmooring-xray:x:{primary}:\nmooring-hy2:x:{primary}:\n"
        ),
    );
    crate::layout::converge(&host.paths, &HostProfile::CURRENT).unwrap();
    for dir in HostProfile::CURRENT.directories {
        let expected = if dir.group == "mooring" {
            other
        } else {
            primary
        };
        assert_eq!(
            fs::metadata(host.paths.at(dir.path)).unwrap().gid(),
            expected,
            "{}",
            dir.path
        );
    }
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

/// Every directory the agent and the watch write is one the layout sets,
/// and the watch's unit lets it write exactly its own.
#[test]
fn the_agent_writes_only_inside_the_layout() {
    let (_dir, paths) = scratch();
    let layout: Vec<std::path::PathBuf> = HostProfile::CURRENT
        .directories
        .iter()
        .map(|dir| paths.at(dir.path))
        .collect();
    for dir in [
        paths.var_lib(),
        paths.blobs(),
        paths.txn_dir(),
        paths.gate_dir(),
        paths.stop_dir(),
        paths.watch_dir(),
        paths.usage_dir(),
        paths.etc(),
        paths.engine_store(),
        paths.agent_dir(),
        paths.geodata_link().parent().unwrap().to_path_buf(),
    ] {
        assert!(layout.contains(&dir), "{}", dir.display());
    }
    let writable: Vec<std::path::PathBuf> = HostProfile::CURRENT
        .watch_writable()
        .iter()
        .map(|dir| paths.at(dir))
        .collect();
    for dir in [
        paths.gate_dir(),
        paths.stop_dir(),
        paths.watch_dir(),
        paths.usage_dir(),
        paths.gate_lock().parent().unwrap().to_path_buf(),
    ] {
        assert!(writable.contains(&dir), "{}", dir.display());
    }
    assert_eq!(paths.stop_request().parent().unwrap(), paths.stop_dir());
    assert_eq!(paths.holds().parent().unwrap(), paths.gate_dir());
}
