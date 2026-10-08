// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared helpers: fixtures, client profiles and deployment edits.

use std::collections::BTreeSet;

use mooring_export::{ExportDocument, ExportFormat, export_user};
use mooring_fixtures::{FIXTURE_NOW, Fixture};
use mooring_model::{
    Capability, ClientLine, ClientProfile, Deployment, DeploymentParts, NodeId, UserId,
};
use saphyr::{LoadableYamlNode as _, YamlOwned};

pub(crate) fn fixtures() -> Vec<Fixture> {
    mooring_fixtures::all().unwrap()
}

pub(crate) fn two_nodes() -> Fixture {
    mooring_fixtures::two_nodes_three_users().unwrap()
}

/// A named client profile.
pub(crate) struct Profile {
    pub(crate) name: &'static str,
    pub(crate) profile: ClientProfile,
}

/// Every profile shape: 0.4, 0.5, and 0.5 with the ML-KEM opt-in.
pub(crate) fn profiles() -> [Profile; 3] {
    [
        Profile {
            name: "cfm04",
            profile: profile(ClientLine::Cfm04, &[]),
        },
        Profile {
            name: "cfm05",
            profile: profile(ClientLine::Cfm05, &[]),
        },
        Profile {
            name: "cfm05-mlkem",
            profile: profile(ClientLine::Cfm05, &[Capability::RealityMlkemOptIn]),
        },
    ]
}

pub(crate) fn profile(line: ClientLine, caps: &[Capability]) -> ClientProfile {
    ClientProfile {
        line,
        capabilities: caps.iter().copied().collect::<BTreeSet<_>>(),
    }
}

pub(crate) fn node(name: &str) -> NodeId {
    NodeId::parse(name).unwrap()
}

/// The fixture's first user (`fxuseraaab`, a CFM 0.4 client).
pub(crate) fn first_user(fixture: &Fixture) -> UserId {
    fixture.deployment.users().keys().next().unwrap().clone()
}

/// The deployment after `change`, revalidated.
pub(crate) fn edited(
    deployment: &Deployment,
    change: impl FnOnce(&mut DeploymentParts),
) -> Deployment {
    let mut parts = deployment.clone().into_parts();
    change(&mut parts);
    Deployment::try_from(parts).unwrap()
}

/// The deployment with `user` switched to `profile`.
pub(crate) fn with_profile(
    deployment: &Deployment,
    user: &UserId,
    profile: &ClientProfile,
) -> Deployment {
    edited(deployment, |parts| {
        for candidate in &mut parts.users {
            if &candidate.id == user {
                candidate.client = profile.clone();
            }
        }
    })
}

pub(crate) fn export(
    fixture: &Fixture,
    deployment: &Deployment,
    user: &UserId,
    format: ExportFormat,
) -> ExportDocument {
    export_user(deployment, &fixture.secrets, user, format, FIXTURE_NOW).unwrap()
}

pub(crate) fn text(document: &ExportDocument) -> &str {
    std::str::from_utf8(document.expose_bytes()).unwrap()
}

/// Parses a document of either format (JSON is YAML 1.2) into one ordered tree.
pub(crate) fn parse(text: &str) -> YamlOwned {
    let mut documents = YamlOwned::load_from_str(text).unwrap();
    assert_eq!(documents.len(), 1, "exactly one document");
    documents.remove(0)
}

/// The keys of a mapping, in document order.
pub(crate) fn keys(value: &YamlOwned) -> Vec<&str> {
    value
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect()
}
