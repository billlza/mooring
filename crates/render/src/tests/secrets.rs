// SPDX-License-Identifier: GPL-3.0-or-later

//! Secret placement: each rendered file carries exactly the secrets its
//! engine needs, credentials never cross nodes (design §12: per-user,
//! per-node credentials), and no `Debug` output shows a secret.

use mooring_model::alerting::AlertSettings;
use mooring_model::secret::{
    Password, SecretEntry, SecretKind, SecretMaterial, SecretRef, SecretSnapshot,
};
use mooring_model::{NodeId, Secret, Uuid};
use zeroize::Zeroizing;

use crate::mac::{exit, prober};
use crate::tests::support::{
    HOST_PRIVATE, cloud_init_keys, edit, engines, fixtures, mac_exit, mac_prober, node, planned,
    secrets_where, vps,
};
use crate::vps::{bundle, cloud_init};

fn needles(secrets: &SecretSnapshot, keep: impl Fn(&SecretRef) -> bool) -> Vec<Zeroizing<String>> {
    secrets_where(secrets, keep).needles()
}

fn assert_absent(text: &str, needles: &[Zeroizing<String>], what: &str) {
    for needle in needles {
        assert!(
            !text.contains(needle.as_str()),
            "{what} holds a foreign secret"
        );
    }
}

fn assert_present(text: &str, needles: &[Zeroizing<String>], what: &str) {
    assert!(!needles.is_empty());
    for needle in needles {
        assert!(
            text.contains(needle.as_str()),
            "{what} lacks a secret it needs"
        );
    }
}

#[test]
fn a_bundle_holds_its_own_nodes_secrets_and_no_others() {
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let bundle = vps(&fixture, id);
            let text: String = bundle
                .files()
                .map(|(_, file)| file.expose_text().to_owned())
                .collect();
            let own = needles(&fixture.secrets, |secret_ref| {
                secret_ref.node() == Some(id)
                    && !matches!(secret_ref, SecretRef::NodeWgMacPrivate(_))
            });
            assert_present(&text, &own, "a VPS bundle");
            let foreign = needles(&fixture.secrets, |secret_ref| {
                secret_ref.node() != Some(id)
                    || matches!(secret_ref, SecretRef::NodeWgMacPrivate(_))
            });
            assert_absent(&text, &foreign, "a VPS bundle");
        }
    }
}

#[test]
fn the_mac_configs_hold_only_what_their_engine_needs() {
    for fixture in fixtures() {
        let exit = mac_exit(&fixture);
        let exit_text = exit.file().expose_text();
        let mac_keys =
            |secret_ref: &SecretRef| matches!(secret_ref, SecretRef::NodeWgMacPrivate(_));
        assert_present(
            exit_text,
            &needles(&fixture.secrets, mac_keys),
            "the exit config",
        );
        assert_absent(
            exit_text,
            &needles(&fixture.secrets, |secret_ref| !mac_keys(secret_ref)),
            "the exit config",
        );
        let prober = mac_prober(&fixture);
        let prober_text = prober.file().expose_text();
        let probe = |secret_ref: &SecretRef| {
            matches!(
                secret_ref,
                SecretRef::ProbeVlessUuid(_)
                    | SecretRef::ProbeHy2Password(_)
                    | SecretRef::NodeHy2Obfs(..)
            )
        };
        assert_present(
            prober_text,
            &needles(&fixture.secrets, probe),
            "the prober config",
        );
        assert_absent(
            prober_text,
            &needles(&fixture.secrets, |secret_ref| !probe(secret_ref)),
            "the prober config",
        );
    }
}

#[test]
fn debug_output_never_shows_a_secret() {
    for fixture in fixtures() {
        let all = fixture.secrets.needles();
        let mut debug = Vec::new();
        for id in fixture.deployment.nodes().keys() {
            debug.push(format!("{:?}", vps(&fixture, id)));
        }
        debug.push(format!("{:?}", mac_exit(&fixture)));
        debug.push(format!("{:?}", mac_prober(&fixture)));
        for text in &debug {
            assert_absent(text, &all, "Debug output");
            assert!(text.contains("RenderedFile"));
        }
    }
    let keys = cloud_init_keys(HOST_PRIVATE);
    let user_data = cloud_init(&planned().deployment, &node("lon1"), &keys).unwrap();
    for text in [format!("{keys:?}"), format!("{user_data:?}")] {
        for line in HOST_PRIVATE
            .lines()
            .filter(|line| !line.starts_with("-----"))
        {
            assert!(!text.contains(line), "Debug output shows the host key");
        }
    }
}

/// The alert channels' secrets reach no rendered file: the deployment's one
/// ntfy topic and each channel node's two checks belong to the node's alert
/// unit (M4), so setting channels up on both nodes leaves every bundle and
/// both Mac configs byte for byte as they were. The snapshot that holds
/// exactly the required secrets, the topic once among them, agrees with
/// `required_secrets` and keeps the topic through a copy.
#[test]
fn alert_channel_secrets_reach_no_rendered_file() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let ids: Vec<NodeId> = fixture.deployment.nodes().keys().cloned().collect();
    assert_eq!(ids.len(), 2);
    let deployment = edit(&fixture.deployment, |parts| {
        let mut alerting = AlertSettings::pilot();
        alerting.channels.extend(ids.iter().cloned());
        parts.alerting = Some(alerting);
    });
    let required = deployment.required_secrets();
    let added: Vec<SecretRef> = required
        .difference(&fixture.deployment.required_secrets())
        .cloned()
        .collect();
    let mut expected = vec![SecretRef::AlertTopic];
    for id in &ids {
        expected.push(SecretRef::NodeDeadManCheck(id.clone()));
        expected.push(SecretRef::NodeMacAliveCheck(id.clone()));
    }
    expected.sort();
    assert_eq!(added, expected);

    let mut secrets = secrets_where(&fixture.secrets, |_| true);
    for (byte, secret_ref) in (0xc1_u8..).zip(&added) {
        let material = if secret_ref.kind() == SecretKind::Password {
            SecretMaterial::Password(Password::from_bytes([byte; 32]).unwrap())
        } else {
            SecretMaterial::Uuid(Secret::new(Uuid::from_random_bytes([byte; 16])))
        };
        secrets
            .insert(SecretEntry::new(secret_ref.clone(), material).unwrap())
            .unwrap();
    }
    assert_eq!(secrets.refs(), required.iter().cloned().collect::<Vec<_>>());
    assert_eq!(secrets.len(), required.len());
    assert_eq!(secrets_where(&secrets, |_| true).refs(), secrets.refs());

    let alert = needles(&secrets, |secret_ref| added.contains(secret_ref));
    assert_eq!(alert.len(), added.len());
    for id in &ids {
        let with_channels = bundle(&deployment, id, &secrets, &engines()).unwrap();
        let without = vps(&fixture, id);
        let files: Vec<_> = with_channels.files().map(|(file, _)| file).collect();
        assert_eq!(
            files,
            without.files().map(|(file, _)| file).collect::<Vec<_>>()
        );
        for (file, rendered) in with_channels.files() {
            assert_eq!(
                rendered.expose_bytes(),
                without.file(file).expose_bytes(),
                "{file:?}"
            );
            assert_absent(rendered.expose_text(), &alert, "a VPS bundle");
        }
    }
    let exit_config = exit(&deployment, &fixture.interfaces, &secrets).unwrap();
    let prober_config = prober(&deployment, &fixture.interfaces, &secrets).unwrap();
    assert_eq!(
        exit_config.file().expose_bytes(),
        mac_exit(&fixture).file().expose_bytes()
    );
    assert_eq!(
        prober_config.file().expose_bytes(),
        mac_prober(&fixture).file().expose_bytes()
    );
    for text in [
        exit_config.file().expose_text(),
        prober_config.file().expose_text(),
    ] {
        assert_absent(text, &alert, "a Mac config");
    }
}
