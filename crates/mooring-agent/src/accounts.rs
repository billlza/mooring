// SPDX-License-Identifier: GPL-3.0-or-later

//! The host profile's accounts (design §5.2, §8.6): read from `/etc/passwd`
//! and `/etc/group`, created and corrected by `Bootstrap` with Debian's own
//! tools, and resolved to ids for the files and directories they own.

use std::fs;

use mooring_agent_proto::{AgentError, BootstrapStep, HostAccount, IoOp, StderrTail};

use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;
use crate::store::{io_error, malformed};

/// What `/etc/passwd` says of one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct User {
    /// The user id.
    pub(crate) uid: u32,
    /// The primary group's id.
    pub(crate) gid: u32,
    /// The home directory.
    pub(crate) home: String,
    /// The login shell.
    pub(crate) shell: String,
}

/// The fields of the line of `text` whose first field is `name`, if any.
/// A database without the file is an error: every Debian host has both.
fn entry(path: &std::path::Path, name: &str) -> Result<Option<Vec<String>>, AgentError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(IoOp::ReadState, &error))?;
    Ok(text.lines().find_map(|line| {
        let fields: Vec<String> = line.split(':').map(str::to_owned).collect();
        (fields.first().map(String::as_str) == Some(name)).then_some(fields)
    }))
}

fn id(field: &str) -> Result<u32, AgentError> {
    field.parse().map_err(|_| malformed(IoOp::ReadState))
}

/// The `/etc/passwd` entry of `name`.
pub(crate) fn user(paths: &Paths, name: &str) -> Result<Option<User>, AgentError> {
    match entry(&paths.passwd(), name)?.as_deref() {
        None => Ok(None),
        Some([_, _, uid, gid, _, home, shell]) => Ok(Some(User {
            uid: id(uid)?,
            gid: id(gid)?,
            home: home.clone(),
            shell: shell.clone(),
        })),
        Some(_) => Err(malformed(IoOp::ReadState)),
    }
}

/// The id of group `name` in `/etc/group`.
pub(crate) fn group_id(paths: &Paths, name: &str) -> Result<Option<u32>, AgentError> {
    match entry(&paths.group(), name)?.as_deref() {
        None => Ok(None),
        Some([_, _, gid, _]) => id(gid).map(Some),
        Some(_) => Err(malformed(IoOp::ReadState)),
    }
}

/// The profile account named `name`, or whose primary group it is.
fn account_of(name: &str) -> Option<HostAccount> {
    HostAccount::ALL
        .iter()
        .copied()
        .find(|account| account.name() == name || account.group() == name)
}

/// What a name the host lacks is: one of the profile's accounts (the node
/// was never bootstrapped, or the account was removed since), or a system
/// database without `root`.
fn missing(name: &str) -> AgentError {
    account_of(name).map_or(malformed(IoOp::ReadState), |account| {
        AgentError::AccountMissing { account }
    })
}

/// The user and group ids of `owner` and `group`.
pub(crate) fn ids(paths: &Paths, owner: &str, group: &str) -> Result<(u32, u32), AgentError> {
    let uid = user(paths, owner)?.ok_or_else(|| missing(owner))?.uid;
    let gid = group_id(paths, group)?.ok_or_else(|| missing(group))?;
    Ok((uid, gid))
}

/// The id of `account`'s primary group.
pub(crate) fn primary_group(paths: &Paths, account: HostAccount) -> Result<u32, AgentError> {
    group_id(paths, account.group())?.ok_or(AgentError::AccountMissing { account })
}

/// Runs one of the account tools; a failure is `Bootstrap{Accounts}` with
/// its stderr.
fn account_tool(node: &dyn Node, tool: Tool, args: &[&str]) -> Result<(), AgentError> {
    match run_ok(node, tool, args)? {
        Ok(_) => Ok(()),
        Err(stderr) => Err(AgentError::Bootstrap {
            step: BootstrapStep::Accounts,
            stderr_tail: StderrTail::scrubbed(&stderr, &[]),
        }),
    }
}

/// Whether `user` is `account` as the profile defines it, with `gid` its
/// primary group's id.
fn conforms(user: &User, account: HostAccount, gid: Option<u32>) -> bool {
    Some(user.gid) == gid && user.home == account.home() && user.shell == account.shell()
}

/// `Bootstrap`'s accounts: every profile account's primary group, then
/// the account with that group, its home and its shell, created where
/// missing and corrected where they differ. The databases are then read
/// again, so an account the tools did not make as the profile says is
/// reported, never assumed.
pub(crate) fn converge(paths: &Paths, node: &dyn Node) -> Result<(), AgentError> {
    for &account in HostAccount::ALL {
        if group_id(paths, account.group())?.is_none() {
            account_tool(node, Tool::Groupadd, &["--system", account.group()])?;
        }
        let (home, shell) = (account.home(), account.shell());
        match user(paths, account.name())? {
            None => account_tool(
                node,
                Tool::Useradd,
                &[
                    "--system",
                    "--no-create-home",
                    "--home-dir",
                    home,
                    "--shell",
                    shell,
                    "--gid",
                    account.group(),
                    account.name(),
                ],
            )?,
            Some(existing) if conforms(&existing, account, group_id(paths, account.group())?) => {}
            Some(_) => account_tool(
                node,
                Tool::Usermod,
                &[
                    "--gid",
                    account.group(),
                    "--home",
                    home,
                    "--shell",
                    shell,
                    account.name(),
                ],
            )?,
        }
    }
    for &account in HostAccount::ALL {
        let user = user(paths, account.name())?.ok_or(AgentError::AccountMissing { account })?;
        if !conforms(&user, account, Some(primary_group(paths, account)?)) {
            return Err(AgentError::Bootstrap {
                step: BootstrapStep::Accounts,
                stderr_tail: StderrTail::scrubbed(
                    format!(
                        "{} still differs from the host profile after usermod",
                        account.name()
                    )
                    .as_bytes(),
                    &[],
                ),
            });
        }
    }
    Ok(())
}
