// SPDX-License-Identifier: GPL-3.0-or-later

//! Every error kind is reachable and named (design §14; `cargo xtask
//! kinds-coverage`). Each kind is produced through the public API, except
//! `Encode`, which the closed document tree cannot trigger and is checked
//! as a constructed value.

use std::collections::BTreeSet;

use mooring_export::{
    ExportError, ExportErrorKind, ExportFormat, OutboundTag, check_certificate, export_user,
    probe_outbounds,
};
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::UnixTime;

use crate::support::{first_user, node, two_nodes};

#[test]
fn every_export_error_kind_is_named_and_described() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let encode = ExportError::Encode(serde_json::from_str::<u8>("x").unwrap_err());
    let produced = [
        (
            ExportErrorKind::InvalidTag,
            OutboundTag::parse("").unwrap_err(),
        ),
        (ExportErrorKind::Encode, encode),
        (
            ExportErrorKind::Model,
            probe_outbounds(&fixture.deployment, &fixture.secrets, &node("nyc1")).unwrap_err(),
        ),
        (
            ExportErrorKind::CertNotCurrent,
            check_certificate(
                fixture.deployment.node(&node("lon1")).unwrap(),
                UnixTime::from_secs(0),
            )
            .unwrap_err(),
        ),
        (
            ExportErrorKind::Secret,
            export_user(
                &fixture.deployment,
                &mooring_model::SecretSnapshot::new(),
                &user,
                ExportFormat::SingBoxJson,
                FIXTURE_NOW,
            )
            .unwrap_err(),
        ),
    ];
    for (kind, error) in &produced {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    // The remaining kinds are produced in refusals.rs and certificates.rs;
    // together they cover every kind.
    let elsewhere = [
        ExportErrorKind::UserNotActive,
        ExportErrorKind::NothingToExport,
        ExportErrorKind::NodeNotApplied,
        ExportErrorKind::CapabilityUnsupported,
        ExportErrorKind::CertUnparseable,
        ExportErrorKind::CertKeyUnsupported,
        ExportErrorKind::CertSanMismatch,
        ExportErrorKind::CertEkuMissing,
    ];
    let covered: BTreeSet<_> = produced
        .iter()
        .map(|(kind, _)| *kind)
        .chain(elsewhere)
        .collect();
    assert_eq!(covered, ExportErrorKind::ALL.iter().copied().collect());
    let names: BTreeSet<_> = ExportErrorKind::ALL
        .iter()
        .map(|kind| kind.name())
        .collect();
    assert_eq!(names.len(), ExportErrorKind::ALL.len());
    assert_eq!(
        ExportErrorKind::CertSanMismatch.to_string(),
        "CertSanMismatch"
    );
}
