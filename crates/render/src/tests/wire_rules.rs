// SPDX-License-Identifier: GPL-3.0-or-later

//! The model and the agent protocol accept exactly the same values for
//! every field they share, so each conversion in `crate::wire` (and the
//! `watch.json` and accounting names) succeeds for every valid value and
//! `RenderError::WireValue` cannot occur; and the conversions themselves.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use mooring_agent_proto as wire;
use mooring_model::dns::DnsName;
use mooring_model::error::ModelError;
use mooring_model::ids::UserId;
use mooring_model::iface::LinuxIfName;
use mooring_model::keys::{Ed25519Pub, PublicKeyKind};
use mooring_model::node::NodeAddress;
use mooring_model::ports::PortRange;
use mooring_model::target::{
    CertificateName, HttpStatus, KeyExchange, TargetAttestation, TargetRejectionKind, TlsOutcome,
    qualify,
};
use proptest::prelude::*;

use crate::error::{RenderError, RenderErrorKind};
use crate::tests::support::{node, vps};
use crate::wire::{adoption_site, header_facts, ssh_ed25519_key, ssh_ed25519_pub, target_facts};

/// Text drawn from an alphabet that exercises every rule: both cases,
/// digits, the DNS and interface punctuation, separators, a space, a
/// control character and a non-ASCII letter.
fn text(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(vec![
            'a', 'z', 'A', 'Z', '0', '9', '-', '.', '_', '/', ':', '+', '@', '*', ' ', '\n', 'é',
        ]),
        0..=max,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Lengths at and around every bound, made of one repeated character.
fn long(c: char) -> impl Strategy<Value = String> {
    (0_usize..=260).prop_map(move |len| std::iter::repeat_n(c, len).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn dns_names_and_target_hosts_accept_the_same_text(
        name in prop_oneof![text(20), long('a'), "[a-z0-9]{1,3}(\\.[a-z0-9]{1,3}){0,3}"]
    ) {
        prop_assert_eq!(DnsName::parse(&name).is_ok(), wire::TargetHost::new(name.clone()).is_ok(), "{:?}", name);
    }

    #[test]
    fn linux_and_wire_interface_names_accept_the_same_text(name in prop_oneof![text(18), long('e')]) {
        prop_assert_eq!(LinuxIfName::parse(&name).is_ok(), wire::IfName::new(name.clone()).is_ok(), "{:?}", name);
    }

    #[test]
    fn certificate_names_accept_the_same_text(name in prop_oneof![text(20), long('c'), long('*')]) {
        prop_assert_eq!(
            CertificateName::parse(&name).is_ok(),
            wire::CertName::new(name.clone()).is_ok(),
            "{:?}", name
        );
    }

    #[test]
    fn port_ranges_accept_the_same_bounds(low in any::<u16>(), high in any::<u16>()) {
        prop_assert_eq!(PortRange::new(low, high).is_ok(), wire::PortRange::new(low, high).is_ok());
    }

    #[test]
    fn every_user_id_is_an_opaque_accounting_name(bits in any::<u64>()) {
        let user = UserId::from_low_bits(bits);
        prop_assert!(wire::OpaqueUserId::new(user.as_str()).is_ok());
    }

    #[test]
    fn ssh_host_keys_convert_to_protocol_lines_and_back(
        bytes in proptest::array::uniform32(any::<u8>())
    ) {
        if let Ok(key) = Ed25519Pub::from_bytes(bytes) {
            let line = ssh_ed25519_key(&key).unwrap();
            prop_assert_eq!(line.as_str(), key.ssh_authorized_key());
            prop_assert_eq!(ssh_ed25519_pub(&line).unwrap(), key);
        }
    }
}

#[test]
fn an_all_zero_ssh_host_key_line_is_refused() {
    let zero = wire::SshEd25519Key::new(format!(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{}",
        "A".repeat(43)
    ))
    .unwrap();
    let error = ssh_ed25519_pub(&zero).unwrap_err();
    assert!(matches!(
        error,
        RenderError::Model(ModelError::InvalidPublicKey {
            key: PublicKeyKind::Ed25519
        })
    ));
}

#[test]
fn http_statuses_accept_the_same_codes() {
    for status in 0..=u16::MAX {
        assert_eq!(
            HttpStatus::new(status).is_ok(),
            wire::HttpStatus::new(status).is_ok(),
            "{status}"
        );
    }
}

#[test]
fn the_wire_names_the_renderers_use_are_valid_model_names() {
    assert!(LinuxIfName::parse(wire::WG_INTERFACE).is_ok());
    for host in ["www.harbour-target.test", "a", "x-1.y2"] {
        assert!(DnsName::parse(host).is_ok() && wire::TargetHost::new(host).is_ok());
    }
}

/// The facts `Hello` reports for a fixture node, as recorded at adoption.
fn hello_for(bundle: &crate::vps::VpsBundle) -> wire::HostFacts {
    let site = bundle.site();
    let facts = &site.host_facts;
    wire::HostFacts {
        uplink: wire::IfName::new(facts.uplink_interface.as_str()).unwrap(),
        vps4: site.address.ipv4(),
        arch: wire::Arch::Amd64,
        ip_local_port_range: wire::PortRange::new(
            facts.ephemeral_ports.start().get(),
            facts.ephemeral_ports.end().get(),
        )
        .unwrap(),
        debian_major: 13,
        kernel: wire::KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
        congestion_control: wire::KernelIdent::new("bbr").unwrap(),
        qdisc: wire::KernelIdent::new("fq").unwrap(),
    }
}

#[test]
fn adoption_records_the_site_hello_reports_and_the_header_carries_it_back() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let bundle = vps(&fixture, &node("lon1"));
    let hello = hello_for(&bundle);
    let site = adoption_site(bundle.site().address, &hello).unwrap();
    assert_eq!(&site, bundle.site());
    assert_eq!(header_facts(&site, &hello).unwrap(), hello);

    let NodeAddress::Public(address) = bundle.site().address;
    let mut elsewhere = hello;
    elsewhere.vps4 = Ipv4Addr::new(45, 67, 89, 99);
    let error = adoption_site(NodeAddress::Public(address), &elsewhere).unwrap_err();
    assert_eq!(error.kind(), RenderErrorKind::AddressNotOnUplink);
    assert!(matches!(
        error,
        RenderError::AddressNotOnUplink { address: a, reported }
            if a == address.get() && reported == Ipv4Addr::new(45, 67, 89, 99)
    ));
}

fn session(group: Option<wire::TlsGroup>) -> wire::TlsSession {
    wire::TlsSession {
        version: wire::TlsVersion::Tls13,
        group,
        chain_bytes: 3_000,
        chain_certs: 2,
        leaf_names: vec![
            wire::CertName::new("*.harbour-target.test").unwrap(),
            wire::CertName::new("WWW.Harbour-Target.test").unwrap(),
        ],
        handshake_p95_micros: 1_800,
        first_flight_bytes: 4_300,
    }
}

fn report(tls: wire::TlsProbe, http: wire::HttpProbe) -> wire::TargetFacts {
    wire::TargetFacts {
        host: wire::TargetHost::new("www.harbour-target.test").unwrap(),
        resolved: BTreeSet::from([Ipv4Addr::new(45, 67, 89, 200)]),
        tls,
        http,
    }
}

fn http_2() -> wire::HttpProbe {
    wire::HttpProbe::Responded {
        status: wire::HttpStatus::new(200).unwrap(),
        version: wire::HttpVersion::Http2,
        redirect: None,
    }
}

fn attestation() -> TargetAttestation {
    TargetAttestation {
        same_asn: true,
        not_cdn: true,
        evidence_url: mooring_model::target::EvidenceUrl::parse("https://evidence.mooring.test/t")
            .unwrap(),
        at: mooring_fixtures::FIXTURE_NOW,
    }
}

fn kinds(facts: &mooring_model::target::TargetFacts) -> Vec<TargetRejectionKind> {
    match qualify(facts, attestation()) {
        Ok(_) => Vec::new(),
        Err(rejected) => rejected.reasons().iter().map(|r| r.kind()).collect(),
    }
}

#[test]
fn every_target_report_outcome_has_a_model_counterpart() {
    let host = DnsName::parse("www.harbour-target.test").unwrap();
    let qualifying = report(
        wire::TlsProbe::Completed(session(Some(wire::TlsGroup::X25519_MLKEM768))),
        http_2(),
    );
    let facts = target_facts(&host, &qualifying).unwrap();
    assert!(
        matches!(&facts.tls, TlsOutcome::Completed(s) if s.key_exchange == KeyExchange::X25519MlKem768 && s.certificate_names.len() == 2)
    );
    assert_eq!(kinds(&facts), []);

    let cases = [
        (
            report(wire::TlsProbe::ConnectFailed, http_2()),
            vec![TargetRejectionKind::TlsConnectFailed],
        ),
        (
            report(wire::TlsProbe::HandshakeFailed, wire::HttpProbe::Failed),
            vec![
                TargetRejectionKind::TlsHandshakeFailed,
                TargetRejectionKind::HttpFailed,
            ],
        ),
        (
            report(wire::TlsProbe::Completed(session(None)), http_2()),
            vec![TargetRejectionKind::UnsupportedKeyExchange],
        ),
        (
            report(
                wire::TlsProbe::Completed(session(Some(wire::TlsGroup::SECP256R1))),
                http_2(),
            ),
            vec![TargetRejectionKind::UnsupportedKeyExchange],
        ),
        (
            wire::TargetFacts {
                resolved: BTreeSet::new(),
                ..report(
                    wire::TlsProbe::Completed(session(Some(wire::TlsGroup::X25519))),
                    http_2(),
                )
            },
            vec![TargetRejectionKind::NoAddress],
        ),
    ];
    for (reported, expected) in cases {
        let facts = target_facts(&host, &reported).unwrap();
        assert_eq!(kinds(&facts), expected, "{reported:?}");
    }

    let other = DnsName::parse("other.harbour-target.test").unwrap();
    let error = target_facts(&other, &qualifying).unwrap_err();
    assert_eq!(error.kind(), RenderErrorKind::TargetFactsForOtherHost);
    assert!(matches!(
        error,
        RenderError::TargetFactsForOtherHost { ref requested, ref reported }
            if *requested == other && reported.as_str() == "www.harbour-target.test"
    ));
    // Not a model error: the requested name itself is valid.
    assert!(!matches!(
        error,
        RenderError::Model(ModelError::InvalidDnsName { .. })
    ));
}
