// SPDX-License-Identifier: GPL-3.0-or-later

//! The user commands (design §15.3) against `state.json` in the support
//! directory: `user add` and `user alias`, `user agree`, which decision F9
//! makes `user export` require, and `user export`.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mooring_export::{ExportError, ExportErrorKind, ExportFormat, export_secret_refs, export_user};
use mooring_keys::{KeysError, credentials};
use mooring_model::ids::MAX_LABEL_CHARS;
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretEntry;
use mooring_model::{
    AgreementRecord, AgreementVersion, Bookkeeping, CalendarDate, Capability, ClientLine,
    ClientProfile, LocalLabel, ModelError, NodeId, StateV2, User, UserId, UserNodePublic,
    UserPolicy, UserStatus,
};
use mooring_store::{ChangeError, Store, StoreError, read_snapshot, update_config_with_secrets};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::prompt::{Console, Line};

fn state_read(error: StoreError) -> LocalError {
    LocalError::StateRead(Box::new(error))
}

/// The state, or `NoState` when this Mac has no deployment yet: no support
/// directory (the store would fail to open its lock there) or no
/// `state.json` in it.
fn load(store: &Store) -> Result<StateV2, LocalError> {
    if !store.dir().is_dir() {
        return Err(LocalError::NoState {
            path: store.state_path(),
        });
    }
    store.load().map_err(|error| match error {
        StoreError::NotInitialized { path } => LocalError::NoState { path },
        other => state_read(other),
    })
}

fn output(error: io::Error) -> CommandError {
    CommandError::Local(LocalError::Output(error))
}

/// A change whose closure cannot refuse: only the store can fail it.
fn state_change(error: ChangeError<Infallible>) -> LocalError {
    match error {
        ChangeError::Store(error) => LocalError::StateChange(Box::new(error)),
        ChangeError::Refused(never) => match never {},
    }
}

fn keys(error: KeysError) -> LocalError {
    LocalError::Keys(error)
}

/// The most bytes read for a label: [`MAX_LABEL_CHARS`] characters of at
/// most four UTF-8 bytes each.
const MAX_LABEL_BYTES: usize = MAX_LABEL_CHARS * 4;

/// The name a message gives a CFM line.
const fn line_name(line: ClientLine) -> &'static str {
    match line {
        ClientLine::Cfm04 => "CFM 0.4",
        ClientLine::Cfm05 => "CFM 0.5",
    }
}

/// `user add [--client cfm05|cfm04] [--mlkem]` (design §9.4, §15.3): adds
/// an active user on `line`, with fresh credentials (a short id, a VLESS
/// UUID, a Hysteria2 password and a loopback UUID) on every node that is
/// not retiring, so that the user holds every node it can be served by.
/// The label is read at the terminal, never from an argument, which the
/// shell history would keep, and is never printed. The user has no alias
/// and no agreement record yet.
///
/// The credentials are written to the keychain before the state that
/// references them (`update_config_with_secrets`); the model refuses a
/// user over the cap, and then nothing is written. Adding a user is a
/// configuration change, so every node needs `node apply` before the
/// user's file can be exported.
pub(crate) fn add(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    line: ClientLine,
    mlkem: bool,
) -> Result<(), CommandError> {
    let capabilities = if mlkem {
        if !line.accepts(Capability::RealityMlkemOptIn) {
            return Err(LocalError::MlkemUnsupported.into());
        }
        BTreeSet::from([Capability::RealityMlkemOptIn])
    } else {
        BTreeSet::new()
    };
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let label = read_label(env.console)?;
    let id = credentials::user_id().map_err(keys)?;
    let mut per_node = BTreeMap::new();
    let mut secrets = Vec::new();
    for node in state.deployment.nodes().values().filter(|node| {
        matches!(
            node.lifecycle,
            NodeLifecycle::Planned | NodeLifecycle::Adopted { .. } | NodeLifecycle::Applied { .. }
        )
    }) {
        per_node.insert(
            node.id.clone(),
            UserNodePublic {
                short_id: credentials::short_id().map_err(keys)?,
            },
        );
        secrets.push(SecretEntry::UserVlessUuid(
            id.clone(),
            node.id.clone(),
            credentials::credential_uuid().map_err(keys)?,
        ));
        secrets.push(SecretEntry::UserHy2Password(
            id.clone(),
            node.id.clone(),
            credentials::password().map_err(keys)?,
        ));
        secrets.push(SecretEntry::UserLoopUuid(
            id.clone(),
            node.id.clone(),
            credentials::credential_uuid().map_err(keys)?,
        ));
    }
    let nodes = per_node
        .keys()
        .map(NodeId::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let user = User {
        id: id.clone(),
        label,
        client: ClientProfile { line, capabilities },
        status: UserStatus::Active,
        per_node,
        policy: UserPolicy::NONE,
        alias: None,
        agreement: None,
    };
    update_config_with_secrets(
        &store,
        env.secrets,
        state.deployment.config_generation(),
        secrets,
        |mut parts| {
            parts.users.push(user);
            Ok(parts)
        },
    )
    .map_err(state_change)?;
    let held = if nodes.is_empty() {
        "no credentials yet: no node is active".to_owned()
    } else {
        format!("credentials on {nodes}")
    };
    out.write_all(
        format!(
            "added user {id}: {}, {held}\nnext: `mooringctl user alias {id}`, then `node apply` each of those nodes, then `user agree` and `user export`\n",
            line_name(line)
        )
        .as_bytes(),
    )
    .map_err(output)
}

/// Reads the user's label at the terminal; it is never taken from an
/// argument.
fn read_label(console: &mut dyn Console) -> Result<LocalLabel, LocalError> {
    let typed = match console.line(
        "Label for this user (kept on this Mac only): ",
        MAX_LABEL_BYTES,
    )? {
        Line::Text(typed) => typed,
        Line::Overlong => return Err(LocalError::Label(ModelError::InvalidLabel)),
        Line::NoTerminal => return Err(LocalError::NoLabelTerminal),
    };
    let text =
        std::str::from_utf8(&typed).map_err(|_| LocalError::Label(ModelError::InvalidLabel))?;
    LocalLabel::parse(text).map_err(LocalError::Label)
}

/// `user alias <uid>` (design §15.3): gives a user without an alias a
/// random one (`xxxx-xxxx`, 40 random bits), which the user and the
/// operator quote instead of a name; an alias is never replaced. The model
/// refuses an alias another user holds. It is a configuration change.
pub(crate) fn alias(env: &Env<'_>, out: &mut dyn Write, user: &UserId) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let existing = state
        .deployment
        .users()
        .get(user)
        .ok_or_else(|| LocalError::UnknownUser { user: user.clone() })?;
    if let Some(alias) = &existing.alias {
        return Err(LocalError::AliasExists {
            user: user.clone(),
            alias: alias.clone(),
        }
        .into());
    }
    let alias = credentials::public_alias().map_err(keys)?;
    store
        .update_config(state.deployment.config_generation(), |mut parts| {
            for candidate in &mut parts.users {
                if candidate.id == *user {
                    candidate.alias = Some(alias.clone());
                }
            }
            Ok(parts)
        })
        .map_err(state_change)?;
    out.write_all(
        format!(
            "user {user} has the alias {alias}; every node it holds needs `node apply` before its next export\n"
        )
        .as_bytes(),
    )
    .map_err(output)
}

/// `user agree <uid>`: records that `user` accepted
/// [`AgreementVersion::CURRENT`] on today's UTC date, as the bookkeeping
/// record `AgreementRecorded` (design §7), which keeps the configuration
/// generation. The store refuses a revoking or revoked user, an older
/// revision and an unknown user, and then changes nothing.
pub(crate) fn agree(env: &Env<'_>, out: &mut dyn Write, user: &UserId) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let today = CalendarDate::utc_of((env.clock)()?).map_err(|_| LocalError::Clock)?;
    let offered = AgreementRecord {
        version: AgreementVersion::CURRENT,
        accepted_on: today,
    };
    let before = state
        .deployment
        .users()
        .get(user)
        .and_then(|record| record.agreement);
    store
        .record(
            state.deployment.config_generation(),
            Bookkeeping::AgreementRecorded {
                user: user.clone(),
                record: offered,
            },
        )
        .map_err(|error| LocalError::StateChange(Box::new(error)))?;
    // The model keeps a record of the same revision with its first day
    // (`Bookkeeping::AgreementRecorded`); the tests hold the two together.
    let line = match before {
        Some(existing) if existing.version == offered.version => format!(
            "kept: user {user} already accepted agreement revision {} on {}\n",
            existing.version, existing.accepted_on
        ),
        Some(_) | None => format!(
            "recorded: user {user} accepted agreement revision {} on {} (UTC); no node apply is needed\n",
            offered.version, offered.accepted_on
        ),
    };
    out.write_all(line.as_bytes()).map_err(output)
}

/// `user export <uid> [--format singbox|clash] --out <path>` (design §9.4):
/// writes the user's file for CFM to a new file with mode 0600, never
/// overwriting one.
///
/// Every check `mooring-export` makes before reading a secret runs first
/// (`export_secret_refs`), then the file and its folder are checked, and
/// only then are exactly the user's secrets read from the keychain: no
/// secret is read for a user who has not accepted the agreement (decision
/// F9, design §9.2) or for a file that cannot be written. A folder in the
/// Desktop, Documents, iCloud Drive or another cloud folder, or one Time
/// Machine backs up, is warned about on `err` (design §12, `delivery.md`
/// section 0); the file is written all the same.
pub(crate) fn export(
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    user: &UserId,
    format: ExportFormat,
    path: &Path,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let now = (env.clock)()?;
    let refs =
        export_secret_refs(&state.deployment, user, now).map_err(|error| refused(user, error))?;
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
    let secrets = read_snapshot(&*env.secrets, &refs)
        .map_err(|error| LocalError::Secrets(Box::new(error)))?;
    let document = export_user(&state.deployment, &secrets, user, format, now)
        .map_err(|error| refused(user, error))?;
    write_new(path, document.expose_bytes())?;
    out.write_all(
        format!(
            "wrote {}: {} for user {user}, mode 0600\ndeliver it as docs/runbooks/delivery.md says, then delete it\n",
            path.display(),
            format.name()
        )
        .as_bytes(),
    )
    .map_err(output)
}

/// A refusal of `mooring-export`; one for the agreement names the command
/// that records it.
fn refused(user: &UserId, error: ExportError) -> CommandError {
    let error = Box::new(error);
    CommandError::Local(if error.kind() == ExportErrorKind::AgreementNotAccepted {
        LocalError::AgreementNotRecorded {
            user: user.clone(),
            source: error,
        }
    } else {
        LocalError::ExportRefused(error)
    })
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
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    write_new_with(path, |file| {
        file.write_all(bytes)?;
        file.sync_all()
    })
}

/// [`write_new`] with the writing given, so the tests can fail it.
fn write_new_with(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
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

    use super::write_new_with;
    use crate::error::{CommandError, LocalError};

    /// A write that fails after the file was created leaves no file.
    #[test]
    fn a_failed_write_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.json");
        let error = write_new_with(&path, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        let CommandError::Local(LocalError::ExportWrite { path: reported, .. }) = error else {
            panic!("{error:?}");
        };
        assert_eq!(reported, path);
        assert!(!path.exists());
    }

    /// If the file cannot be removed either, the error says so and names
    /// the file to delete by hand.
    #[test]
    fn a_file_that_cannot_be_removed_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.json");
        let error = write_new_with(&path, |_| {
            // A folder without write permission keeps its entries.
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(path.exists());
        let CommandError::Local(local @ LocalError::ExportLeftBehind { .. }) = error else {
            panic!("{error:?}");
        };
        assert!(
            local
                .to_string()
                .ends_with("cannot remove what was written (Permission denied (os error 13)): delete the file by hand"),
            "{local}"
        );
    }
}
