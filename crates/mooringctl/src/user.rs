// SPDX-License-Identifier: GPL-3.0-or-later

//! The user commands (design §15.3) against `state.json` in the support
//! directory: `user add` and `user alias`, `user agree`, which decision F9
//! makes `user export` require, `user export`, and `user export-profiles`,
//! the portal's bundle of every served user's file (design §9.5).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use mooring_export::{
    ExportError, ExportErrorKind, ExportFormat, ProfileSelection, ProfilesError, Withheld,
    export_secret_refs, export_user, profile_selection,
};
use mooring_keys::credentials;
use mooring_model::ids::MAX_LABEL_CHARS;
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretEntry;
use mooring_model::{
    AgreementRecord, AgreementVersion, Bookkeeping, CalendarDate, Capability, ClientLine,
    ClientProfile, Deployment, LocalLabel, ModelError, NodeId, StateV3, SuspendReason, User,
    UserId, UserNodePublic, UserPolicy, UserStatus,
};
use mooring_store::{Store, read_snapshot, update_config_with_secrets};

use crate::app::{Env, support_dir};
use crate::cli::SuspendArg;
use crate::error::{CommandError, LocalError};
use crate::export_file;
use crate::prompt::{Console, Line};
use crate::state::{load, output, refused_change, state_change, store_failure};

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
/// A Mac with no deployment, or a state that cannot be read, is refused
/// before the label is asked for. The label may wait as long as the
/// operator takes to type it, so the state the user is added to is read
/// once it is there: a planned node cancelled meanwhile is gone with a
/// record that keeps the generation (`node cancel`), and a user given
/// credentials on it from an earlier read would be refused by the store
/// (`UnknownNode`), after the label was typed.
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
    load(&store)?;
    let label = read_label(env.console)?;
    let state = load(&store)?;
    let id = fresh_user_id(&state.deployment)?;
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
                short_id: credentials::short_id().map_err(LocalError::Keys)?,
            },
        );
        secrets.push(SecretEntry::UserVlessUuid(
            id.clone(),
            node.id.clone(),
            credentials::credential_uuid().map_err(LocalError::Keys)?,
        ));
        secrets.push(SecretEntry::UserHy2Password(
            id.clone(),
            node.id.clone(),
            credentials::password().map_err(LocalError::Keys)?,
        ));
        secrets.push(SecretEntry::UserLoopUuid(
            id.clone(),
            node.id.clone(),
            credentials::credential_uuid().map_err(LocalError::Keys)?,
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
    let alias = credentials::public_alias().map_err(LocalError::Keys)?;
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

/// The most ids `user add` draws for a user whose source address inside
/// the nodes no user has (design §11.8): with 131,070 addresses and a few
/// users, a working random source needs a second draw about once in tens
/// of thousands of users.
const USER_ID_DRAWS: usize = 16;

/// A random user id whose source address inside the nodes
/// ([`mooring_agent_proto::user_source`]) no user of `deployment` has,
/// whatever their status, so the renderer never meets two served users
/// sharing one (`UserSourceCollision`).
fn fresh_user_id(deployment: &Deployment) -> Result<UserId, LocalError> {
    fresh_user_id_from(deployment, || {
        credentials::user_id().map_err(LocalError::Keys)
    })
}

/// [`fresh_user_id`] with the ids drawn by `draw`.
pub(crate) fn fresh_user_id_from(
    deployment: &Deployment,
    mut draw: impl FnMut() -> Result<UserId, LocalError>,
) -> Result<UserId, LocalError> {
    let source = |user: &UserId| {
        mooring_agent_proto::OpaqueUserId::new(user.as_str())
            .map(|opaque| mooring_agent_proto::user_source(&opaque))
            .ok()
    };
    let taken: BTreeSet<_> = deployment.users().keys().filter_map(source).collect();
    for _ in 0..USER_ID_DRAWS {
        let id = draw()?;
        if source(&id).is_some_and(|address| !taken.contains(&address)) {
            return Ok(id);
        }
    }
    Err(LocalError::NoFreeUserSource)
}

/// `user suspend <uid> --reason …`: suspends an active user, as of now, for
/// an abuse review or another reason of the operator's (design §7, §11.8).
/// A configuration change: every node the user holds needs `node apply`.
pub(crate) fn suspend(
    env: &Env<'_>,
    out: &mut dyn Write,
    user: &UserId,
    reason: SuspendArg,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let now = (env.clock)()?;
    let reason = match reason {
        SuspendArg::AbuseReview => SuspendReason::AbuseReview,
        SuspendArg::Operator => SuspendReason::Operator,
    };
    change_status(&store, &state, user, |found| found.suspend(reason, now))?;
    writeln!(
        out,
        "user {user} is suspended ({}); every node it holds needs `node apply` before it is served no more",
        match reason {
            SuspendReason::AbuseReview => "abuse review",
            _ => "operator",
        }
    )
    .map_err(output)
}

/// `user resume <uid>`: resumes a suspended user, within the cap. A
/// configuration change: every node the user holds needs `node apply`.
pub(crate) fn resume(
    env: &Env<'_>,
    out: &mut dyn Write,
    user: &UserId,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    change_status(&store, &state, user, User::resume)?;
    writeln!(
        out,
        "user {user} is active; every node it holds needs `node apply` before it is served again"
    )
    .map_err(output)
}

/// Applies a status transition of the model's to `user`, as one
/// configuration change; the model's refusal is
/// [`LocalError::UserTransition`], and the cap's is the store's.
fn change_status(
    store: &Store,
    state: &StateV3,
    user: &UserId,
    transition: impl Fn(&mut User) -> Result<(), ModelError>,
) -> Result<(), CommandError> {
    if !state.deployment.users().contains_key(user) {
        return Err(LocalError::UnknownUser { user: user.clone() }.into());
    }
    store
        .update_config(state.deployment.config_generation(), |mut parts| {
            for candidate in &mut parts.users {
                if candidate.id == *user {
                    transition(candidate).map_err(|source| LocalError::UserTransition {
                        user: user.clone(),
                        source,
                    })?;
                }
            }
            Ok(parts)
        })
        .map_err(refused_change)?;
    Ok(())
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
        .map_err(store_failure)?;
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
    export_file::prepare(env, err, path)?;
    let secrets = read_snapshot(&*env.secrets, &refs)
        .map_err(|error| LocalError::Secrets(Box::new(error)))?;
    let document = export_user(&state.deployment, &secrets, user, format, now)
        .map_err(|error| refused(user, error))?;
    export_file::write_new(path, document.expose_bytes())?;
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

/// `user export-profiles --user <id>... --out <path>` (design §9.5): writes
/// the portal's profile bundle of the users named, each one's CFM file or
/// why it is withheld, to a new file with mode 0600, never overwriting one.
///
/// Refused first while the agreement this build ships does not cover the
/// portal. Then every check `mooring-export` makes before reading a secret
/// runs (`profile_selection`): the users named are distinct users, and
/// each one to be delivered can have a file. The file and its folder are
/// checked as for `user export`, and only then are exactly the delivered
/// users' secrets read from the keychain. A user to be delivered whose
/// file cannot be made refuses the whole bundle; each user withheld is
/// named with the reason and what the portal's import does to their
/// subscription link.
pub(crate) fn export_profiles(
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    users: &[UserId],
    path: &Path,
) -> Result<(), CommandError> {
    env.portal_agreement
        .required()
        .map_err(LocalError::PortalNotCovered)?;
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let now = (env.clock)()?;
    let selection = profile_selection(&state.deployment, users, now, env.portal_agreement)
        .map_err(profiles_refused)?;
    export_file::prepare(env, err, path)?;
    let secrets = read_snapshot(&*env.secrets, selection.secret_refs())
        .map_err(|error| LocalError::ProfilesSecrets(Box::new(error)))?;
    let bundle = mooring_export::export_profiles(
        &state.deployment,
        &secrets,
        users,
        now,
        env.portal_agreement,
    )
    .map_err(profiles_refused)?;
    export_file::write_new(path, bundle.expose_bytes())?;
    out.write_all(profiles_summary(path, bundle.selection()).as_bytes())
        .map_err(output)
}

/// What `user export-profiles` says once the bundle at `path` is written:
/// how many users it delivers, each user it withholds, why, and what the
/// portal's import does to their link, and where the file goes.
fn profiles_summary(path: &Path, selection: &ProfileSelection) -> String {
    let withheld = selection.withheld();
    let named: String = withheld
        .iter()
        .map(|(user, why)| {
            format!(
                "withheld: user {user} ({why}); importing it {}\n",
                link_at_import(why)
            )
        })
        .collect();
    format!(
        "wrote {}: CFM profiles of {} user(s) and {} withheld, sing-box-json, mode 0600\n{named}import it with `mooring-portal import-profiles` on the portal host, then delete it\n",
        path.display(),
        selection.delivered().len(),
        withheld.len(),
    )
}

/// What the portal's import does to the subscription link of a user
/// withheld for `why` (the operator's decision, 2026-11-06): a suspension,
/// whatever its reason, or a missing acceptance only pauses it, until a
/// bundle delivers the user again; a revocation ends it for good.
const fn link_at_import(why: &Withheld) -> &'static str {
    match why {
        Withheld::Suspended | Withheld::AgreementNotAccepted { .. } => {
            "pauses their subscription link until a bundle delivers them again"
        }
        Withheld::BeingRevoked | Withheld::Revoked => "ends their subscription link for good",
    }
}

/// A refusal of the profile bundle.
fn profiles_refused(error: ProfilesError) -> CommandError {
    CommandError::Local(LocalError::ProfilesRefused(Box::new(error)))
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
