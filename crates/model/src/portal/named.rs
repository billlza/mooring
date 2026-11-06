// SPDX-License-Identifier: GPL-3.0-or-later

//! The users a portal export holds (design §9.5): exactly those the
//! operator names, by id, and no others. Neither the snapshot nor the
//! profile bundle ever holds every user by default. Both refuse a list
//! that names no one, an id no user has, or one user twice, rather than
//! export another set than the one named.

use std::collections::BTreeMap;

use crate::deployment::Deployment;
use crate::ids::UserId;
use crate::kinds;
use crate::user::User;

/// The users `users` names, in id order: at least one, each a user of
/// `deployment`, none named twice. Refused at the first id, in the order
/// given, that no user has or that was named before it.
pub fn named_users<'a>(
    deployment: &'a Deployment,
    users: &[UserId],
) -> Result<BTreeMap<&'a UserId, &'a User>, NamedUsersError> {
    if users.is_empty() {
        return Err(NamedUsersError::NoUsers);
    }
    let mut named = BTreeMap::new();
    for id in users {
        let (id, user) = deployment
            .users()
            .get_key_value(id)
            .ok_or_else(|| NamedUsersError::UnknownUser { user: id.clone() })?;
        if named.insert(id, user).is_some() {
            return Err(NamedUsersError::DuplicateUser { user: id.clone() });
        }
    }
    Ok(named)
}

/// The users named for a portal export are not a list of distinct users
/// of the deployment, so nothing is exported.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NamedUsersError {
    /// No user was named.
    #[error("no user was named; a portal export holds only the users named")]
    NoUsers,
    /// No user has this id.
    #[error("unknown user {user}")]
    UnknownUser {
        /// The id given.
        user: UserId,
    },
    /// A user was named twice.
    #[error("user {user} is named twice")]
    DuplicateUser {
        /// The user.
        user: UserId,
    },
}

kinds! {
    /// The kind of a [`NamedUsersError`], without its details.
    pub enum NamedUsersErrorKind {
        /// See [`NamedUsersError::NoUsers`].
        NoUsers,
        /// See [`NamedUsersError::UnknownUser`].
        UnknownUser,
        /// See [`NamedUsersError::DuplicateUser`].
        DuplicateUser,
    }
}

impl NamedUsersError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> NamedUsersErrorKind {
        match self {
            Self::NoUsers => NamedUsersErrorKind::NoUsers,
            Self::UnknownUser { .. } => NamedUsersErrorKind::UnknownUser,
            Self::DuplicateUser { .. } => NamedUsersErrorKind::DuplicateUser,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{two_node_parts, user_id};

    fn deployment() -> Deployment {
        Deployment::try_from(two_node_parts()).unwrap()
    }

    /// The users named come back in id order, whatever the order given,
    /// and only those.
    #[test]
    fn the_users_named_come_back_in_id_order_and_only_they() {
        let deployment = deployment();
        let (first, second) = (user_id(1), user_id(2));
        assert!(first < second);
        let named = named_users(&deployment, &[second.clone(), first.clone()]).unwrap();
        assert_eq!(named.keys().copied().collect::<Vec<_>>(), [&first, &second]);
        assert_eq!(named[&first], &deployment.users()[&first]);
        let one = named_users(&deployment, std::slice::from_ref(&second)).unwrap();
        assert_eq!(one.keys().copied().collect::<Vec<_>>(), [&second]);
    }

    /// No one named, an id no user has and a user named twice are each
    /// refused, at the first id that breaks the rule.
    #[test]
    fn an_empty_list_an_unknown_id_and_a_repeat_are_refused() {
        let deployment = deployment();
        let (first, unknown) = (user_id(1), user_id(3));
        let cases = [
            (
                Vec::new(),
                NamedUsersError::NoUsers,
                NamedUsersErrorKind::NoUsers,
            ),
            (
                vec![first.clone(), unknown.clone(), first.clone()],
                NamedUsersError::UnknownUser {
                    user: unknown.clone(),
                },
                NamedUsersErrorKind::UnknownUser,
            ),
            (
                vec![first.clone(), first.clone(), unknown],
                NamedUsersError::DuplicateUser {
                    user: first.clone(),
                },
                NamedUsersErrorKind::DuplicateUser,
            ),
        ];
        assert_eq!(cases.len(), NamedUsersErrorKind::ALL.len());
        for (users, error, kind) in cases {
            assert_eq!(named_users(&deployment, &users), Err(error.clone()));
            assert_eq!(error.kind(), kind);
        }
    }

    #[test]
    fn each_refusal_names_the_id() {
        let user = user_id(1);
        assert_eq!(
            NamedUsersError::NoUsers.to_string(),
            "no user was named; a portal export holds only the users named"
        );
        assert_eq!(
            NamedUsersError::UnknownUser { user: user.clone() }.to_string(),
            format!("unknown user {user}")
        );
        assert_eq!(
            NamedUsersError::DuplicateUser { user: user.clone() }.to_string(),
            format!("user {user} is named twice")
        );
    }
}
