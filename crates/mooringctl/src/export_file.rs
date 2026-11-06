// SPDX-License-Identifier: GPL-3.0-or-later

//! The file an export writes (design §9.4, §12; `delivery.md` section 0):
//! a new file with mode 0600, never one that exists, removed again when
//! writing it fails, in a folder checked first against the synced folders
//! and Time Machine. Every export command writes its file through here.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::state::output;

/// Checks that nothing is at `path`, a link included, and warns on `err`
/// about its folder: one in the Desktop, Documents, iCloud Drive or another
/// cloud folder, or one Time Machine backs up (design §12, `delivery.md`
/// section 0). The file is written all the same. An export calls it once
/// every check of what goes in the file has passed and before it reads any
/// secret, so that no secret is read for a file that cannot be written.
pub(crate) fn prepare(env: &Env<'_>, err: &mut dyn Write, path: &Path) -> Result<(), CommandError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(LocalError::ExportExists {
                path: path.to_path_buf(),
            }
            .into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(LocalError::ExportFolder {
                path: path.to_path_buf(),
                source,
            }
            .into());
        }
    }
    let folder = folder_of(path)?;
    for warning in warnings(env, &folder) {
        err.write_all(format!("mooringctl: warning: {warning}\n").as_bytes())
            .map_err(output)?;
    }
    Ok(())
}

/// The folder `path` goes in, with every link resolved.
fn folder_of(path: &Path) -> Result<PathBuf, CommandError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        Some(_) | None => Path::new("."),
    };
    fs::canonicalize(parent).map_err(|source| {
        CommandError::Local(LocalError::ExportFolder {
            path: path.to_path_buf(),
            source,
        })
    })
}

/// Where exports must not go (`delivery.md`, section 0): synced folders,
/// with the name each warning gives them, under the user's home.
const SYNCED_FOLDERS: [(&str, &str); 4] = [
    ("Library/Mobile Documents", "iCloud Drive"),
    ("Library/CloudStorage", "a cloud storage folder"),
    ("Desktop", "the Desktop"),
    ("Documents", "Documents"),
];

/// The warnings about `folder`: whether it is synced, and whether Time
/// Machine excludes it.
fn warnings(env: &Env<'_>, folder: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let home = env
        .home
        .as_deref()
        .map(Path::new)
        .and_then(|home| fs::canonicalize(home).ok());
    if let Some(home) = home
        && let Some((_, place)) = SYNCED_FOLDERS
            .iter()
            .find(|(relative, _)| folder.starts_with(home.join(relative)))
    {
        warnings.push(format!(
            "{} is in {place}; keep exports in a folder outside iCloud Drive, the Desktop and Documents (docs/runbooks/delivery.md, section 0)",
            folder.display()
        ));
    }
    let dir = folder.display();
    match env.backups.is_excluded(folder) {
        Ok(true) => {}
        Ok(false) => warnings.push(format!(
            "Time Machine backs up {dir}; exclude it with `tmutil addexclusion {dir}`"
        )),
        Err(error) => warnings.push(format!(
            "cannot tell whether Time Machine excludes {dir}: {error}"
        )),
    }
    warnings
}

/// Creates `path` with mode 0600 and writes `bytes`; on a failure after it
/// was created, removes it, because it would hold the user's credentials.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    write_new_with(path, &mut |file| {
        file.write_all(bytes)?;
        file.sync_all()
    })
}

/// [`write_new`] with the writing given, so the tests can fail it (one
/// function, not one per closure, so every caller runs the same code).
fn write_new_with(
    path: &Path,
    write: &mut dyn FnMut(&mut fs::File) -> io::Result<()>,
) -> Result<(), CommandError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| {
            CommandError::Local(if source.kind() == io::ErrorKind::AlreadyExists {
                LocalError::ExportExists {
                    path: path.to_path_buf(),
                }
            } else {
                LocalError::ExportWrite {
                    path: path.to_path_buf(),
                    source,
                }
            })
        })?;
    let written = write(&mut file);
    drop(file);
    let Err(source) = written else {
        return Ok(());
    };
    Err(CommandError::Local(match fs::remove_file(path) {
        Ok(()) => LocalError::ExportWrite {
            path: path.to_path_buf(),
            source,
        },
        Err(removal) => LocalError::ExportLeftBehind {
            path: path.to_path_buf(),
            removal,
            source,
        },
    }))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::{folder_of, write_new, write_new_with};
    use crate::error::{CommandError, LocalError};

    /// A write that fails after the file was created leaves no file.
    #[test]
    fn a_failed_write_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.json");
        let error = write_new_with(&path, &mut |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        assert!(
            matches!(&error, CommandError::Local(LocalError::ExportWrite { path: reported, .. }) if *reported == path),
            "{error:?}"
        );
        assert!(!path.exists());
    }

    /// If the file cannot be removed either, the error says so and names
    /// the file to delete by hand.
    #[test]
    fn a_file_that_cannot_be_removed_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.json");
        let error = write_new_with(&path, &mut |_| {
            // A folder without write permission keeps its entries.
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(path.exists());
        assert!(
            matches!(&error, CommandError::Local(LocalError::ExportLeftBehind { path: reported, removal, source })
                if *reported == path && removal.kind() == io::ErrorKind::PermissionDenied
                    && source.to_string() == "disk full"),
            "{error:?}"
        );
        assert!(
            error
                .to_string()
                .ends_with("cannot remove what was written (Permission denied (os error 13)): delete the file by hand"),
            "{error}"
        );
    }

    /// A file that appeared since the check is never overwritten, and a
    /// file that cannot be made is the write's failure; neither is written.
    #[test]
    fn a_file_that_exists_or_cannot_be_made_is_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.json");
        fs::write(&path, b"earlier").unwrap();
        let error = write_new(&path, b"the user's file").unwrap_err();
        assert!(
            matches!(&error, CommandError::Local(LocalError::ExportExists { path: reported }) if *reported == path),
            "{error:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"earlier");
        let missing = dir.path().join("missing").join("user.json");
        let error = write_new(&missing, b"the user's file").unwrap_err();
        assert!(
            matches!(&error, CommandError::Local(LocalError::ExportWrite { path: reported, source }) if *reported == missing && source.kind() == io::ErrorKind::NotFound),
            "{error:?}"
        );
        assert!(!missing.exists());
    }

    /// A file named without a folder goes in the current one.
    #[test]
    fn a_bare_file_name_goes_in_the_current_folder() {
        let current = fs::canonicalize(".").unwrap();
        assert_eq!(folder_of(Path::new("user.json")).unwrap(), current);
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            folder_of(&dir.path().join("user.json")).unwrap(),
            fs::canonicalize(dir.path()).unwrap()
        );
    }
}
