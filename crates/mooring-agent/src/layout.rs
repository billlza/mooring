// SPDX-License-Identifier: GPL-3.0-or-later

//! The agent's directories ([`HostProfile::directories`], design §11.3):
//! `Bootstrap` creates each where it is missing and then sets its owner,
//! group and mode, so a second run repairs whatever was changed since.

use std::fs;
use std::os::unix::fs::{PermissionsExt, chown};

use mooring_agent_proto::{AgentError, HostProfile, IoOp};

use crate::accounts;
use crate::paths::Paths;
use crate::store::{io_error, malformed};

/// Creates and sets every directory of the profile's layout, parents
/// first. A path that exists as anything but a directory (a file, a
/// symbolic link) is refused rather than followed.
pub(crate) fn converge(paths: &Paths, profile: &HostProfile) -> Result<(), AgentError> {
    let fail = |error: std::io::Error| io_error(IoOp::WriteState, &error);
    for dir in profile.directories {
        let path = paths.at(dir.path);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(malformed(IoOp::WriteState)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&path).map_err(fail)?;
            }
            Err(error) => return Err(fail(error)),
        }
        let (uid, gid) = accounts::ids(paths, dir.owner, dir.group)?;
        chown(&path, Some(uid), Some(gid)).map_err(fail)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(dir.mode)).map_err(fail)?;
    }
    Ok(())
}
