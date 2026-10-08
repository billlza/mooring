// SPDX-License-Identifier: GPL-3.0-or-later

//! Secret placement: each rendered file carries exactly the secrets its
//! engine needs, credentials never cross nodes (design §12: per-user,
//! per-node credentials), and no `Debug` output shows a secret.

use mooring_model::secret::{SecretRef, SecretSnapshot};
use zeroize::Zeroizing;

use crate::tests::support::{
    HOST_PRIVATE, cloud_init_keys, fixtures, mac_exit, mac_prober, node, planned, secrets_where,
    vps,
};
use crate::vps::cloud_init;

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
                secret_ref.node() == id && !matches!(secret_ref, SecretRef::NodeWgMacPrivate(_))
            });
            assert_present(&text, &own, "a VPS bundle");
            let foreign = needles(&fixture.secrets, |secret_ref| {
                secret_ref.node() != id || matches!(secret_ref, SecretRef::NodeWgMacPrivate(_))
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
