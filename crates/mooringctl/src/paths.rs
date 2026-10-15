// SPDX-License-Identifier: GPL-3.0-or-later

//! The support directory (design §7): `~/Library/Application
//! Support/Mooring`, where the router identity lives beside `state.json`.

use std::ffi::OsString;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::error::LocalError;

/// The support directory under `home`, which must be an absolute path
/// (`Home` if `HOME` is unset, empty or relative).
pub(crate) fn support_dir(home: Option<OsString>) -> Result<PathBuf, LocalError> {
    let home = PathBuf::from(home.ok_or(LocalError::Home)?);
    if !home.is_absolute() {
        return Err(LocalError::Home);
    }
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Mooring"))
}

/// Creates the support directory and any missing parent with mode 0700;
/// an existing directory is left as it is.
pub(crate) fn create_support_dir(dir: &Path) -> Result<(), LocalError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|source| LocalError::SupportDir {
            path: dir.to_path_buf(),
            source,
        })
}
