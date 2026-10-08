// SPDX-License-Identifier: GPL-3.0-or-later

use mooring_model::ModelError;
use mooring_model::secret::SecretKind;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::error::KeysErrorKind;
use crate::testing::{CountingRandom, FailingRandom, ZeroRandom, hex};

#[cfg(target_os = "macos")]
mod tools;

/// Comments whose lengths 0..=8 produce every padding length 0..=7.
const PADDING_COMMENTS: [&str; 9] = [
    "", "a", "ab", "abc", "abcd", "abcde", "abcdef", "mooring", "ops@lon1",
];

fn comment(text: &str) -> SshComment {
    SshComment::parse(text).unwrap()
}

/// The test-side reader for the SSH wire format.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> &'a [u8] {
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        head
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    fn string(&mut self) -> &'a [u8] {
        let len = usize::try_from(self.u32()).unwrap();
        self.take(len)
    }
}

/// The fields of an unencrypted single-key `openssh-key-v1` file.
#[derive(Debug)]
struct Decoded {
    check: [u32; 2],
    seed: [u8; 32],
    public: [u8; 32],
    comment: String,
    padding: Vec<u8>,
    section_len: usize,
}

/// Decodes a private key file the way `sshkey_parse_private2` reads it,
/// asserting every fixed field.
fn decode(text: &str) -> Decoded {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    assert_eq!(lines.first(), Some(&PEM_BEGIN));
    assert_eq!(lines.last(), Some(&PEM_END));
    let body: Vec<&str> = lines[1..lines.len() - 1]
        .iter()
        .map(|line| line.strip_suffix('\n').unwrap())
        .collect();
    let (last, full) = body.split_last().unwrap();
    assert!(full.iter().all(|line| line.len() == 70));
    assert!((1..=70).contains(&last.len()));
    let bytes = STANDARD.decode(body.concat()).unwrap();

    let mut file = Reader(&bytes);
    assert_eq!(file.take(15), b"openssh-key-v1\0");
    assert_eq!(file.string(), b"none");
    assert_eq!(file.string(), b"none");
    assert_eq!(file.string(), b"");
    assert_eq!(file.u32(), 1);
    let blob = file.string();
    let section = file.string();
    assert!(file.0.is_empty());

    let mut key = Reader(blob);
    assert_eq!(key.string(), b"ssh-ed25519");
    let public: [u8; 32] = key.string().try_into().unwrap();
    assert!(key.0.is_empty());

    let mut private = Reader(section);
    let check = [private.u32(), private.u32()];
    assert_eq!(private.string(), b"ssh-ed25519");
    assert_eq!(private.string(), public);
    let secret = private.string();
    assert_eq!(secret.len(), 64);
    assert_eq!(&secret[32..], public);
    let comment = String::from_utf8(private.string().to_vec()).unwrap();
    Decoded {
        check,
        seed: secret[..32].try_into().unwrap(),
        public,
        comment,
        padding: private.0.to_vec(),
        section_len: section.len(),
    }
}

#[test]
fn rfc8032_section_7_1_test_1() {
    let seed = Ed25519Seed::from_bytes(hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
    .unwrap();
    let pair = SshKeyPair::from_seed(seed).unwrap();
    assert_eq!(
        *pair.public().key().as_bytes(),
        hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
}

/// An independent vector from OpenSSL 3.6.4 (`crates/fixtures/src/material.rs`):
/// the seed is the SHA-256 of a label.
#[test]
fn openssl_derived_host_key_vector() {
    let seed: [u8; 32] = Sha256::digest(b"mooring-fixture/lon1/ssh-host-ed25519").into();
    let pair = SshKeyPair::generate_from(&mut crate::testing::ReplayRandom::new(&seed)).unwrap();
    assert_eq!(
        pair.public().key().to_string(),
        "4trWfS1sIdDIQszRK7tOeduPECAXUYbE8AD8k1RmExs="
    );
    assert_eq!(*pair.seed().expose_bytes(), seed);
}

#[test]
fn public_encodings_have_the_openssh_layout() {
    let pair = SshKeyPair::generate_from(&mut CountingRandom::starting_at(9)).unwrap();
    let public = pair.public();
    let blob = public.key().ssh_blob();
    assert_eq!(&blob[..4], [0, 0, 0, 11]);
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], [0, 0, 0, 32]);
    assert_eq!(&blob[19..], public.key().as_bytes());

    // The agent protocol's structural rule for `ops_pubkey` (agent-proto
    // `SshEd25519Key`): 68 base64 characters after a fixed 25-character prefix.
    let key = public.authorized_key();
    let encoded = key.strip_prefix("ssh-ed25519 ").unwrap();
    assert_eq!(encoded.len(), 68);
    assert!(encoded.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI"));
    assert!((b'A'..=b'P').contains(&encoded.as_bytes()[25]));
    assert_eq!(STANDARD.decode(encoded).unwrap(), blob);

    assert_eq!(public.line(&SshComment::default()), key);
    assert_eq!(
        public.line(&comment("mooring-ops@lon1")),
        format!("{key} mooring-ops@lon1")
    );
    assert_eq!(
        public.known_hosts_line(Ipv4Addr::new(203, 0, 113, 7)),
        format!("203.0.113.7 {key}")
    );

    let fingerprint = public.fingerprint();
    let digest: [u8; 32] = Sha256::digest(blob).into();
    assert_eq!(*fingerprint.as_bytes(), digest);
    let text = fingerprint.to_string();
    assert_eq!(text.len(), 7 + 43);
    assert_eq!(
        text,
        format!("SHA256:{}", STANDARD.encode(digest).trim_end_matches('='))
    );
    assert_eq!(SshPublicKey::from(public.key()), public);
    assert_eq!(SshPublicKey::new(public.key()), public);
}

#[test]
fn comment_rule() {
    for ok in ["", "mooring-ops@lon1", "a.b_c+d-e", &"x".repeat(64)] {
        assert_eq!(SshComment::parse(ok).unwrap().as_str(), ok);
    }
    for bad in [
        "two words",
        "line\nbreak",
        "tab\there",
        "comma,separated",
        "quote\"d",
        "#hash",
        "caf\u{e9}",
        &"x".repeat(65),
    ] {
        assert_eq!(
            SshComment::parse(bad),
            Err(KeysError::InvalidSshComment),
            "{bad:?}"
        );
    }
    assert_eq!(
        SshComment::parse(" ").unwrap_err().kind(),
        KeysErrorKind::InvalidSshComment
    );
}

#[test]
fn private_key_layout_and_padding() {
    let pair = SshKeyPair::generate_from(&mut CountingRandom::starting_at(200)).unwrap();
    let mut paddings = Vec::new();
    for text in PADDING_COMMENTS {
        let encoded = pair.encode_private_key(&comment(text), 0x0102_0304);
        let decoded = decode(encoded.expose_pem());
        assert_eq!(decoded.check, [0x0102_0304; 2]);
        assert_eq!(decoded.seed, *pair.seed().expose_bytes());
        assert_eq!(decoded.public, *pair.public().key().as_bytes());
        assert_eq!(decoded.comment, text);
        assert_eq!(decoded.section_len % 8, 0, "{text:?}");
        let expected: Vec<u8> = (1..=u8::try_from(decoded.padding.len()).unwrap()).collect();
        assert_eq!(decoded.padding, expected, "{text:?}");
        paddings.push(decoded.padding.len());
    }
    paddings.sort_unstable();
    assert_eq!(paddings, [0, 1, 2, 3, 4, 5, 5, 6, 7]);

    // The longest comment still fits the documented bound.
    let longest = pair.encode_private_key(&comment(&"z".repeat(64)), 7);
    assert_eq!(decode(longest.expose_pem()).section_len, 200);
}

#[test]
fn the_check_integer_comes_from_the_random_source() {
    let pair = SshKeyPair::generate_from(&mut CountingRandom::starting_at(1)).unwrap();
    let encoded = pair
        .openssh_private_key_from(
            &mut CountingRandom::starting_at(0xa0),
            &SshComment::default(),
        )
        .unwrap();
    assert_eq!(decode(encoded.expose_pem()).check, [0xa0a1_a2a3; 2]);
    assert_eq!(
        pair.openssh_private_key_from(&mut FailingRandom, &SshComment::default()),
        Err(KeysError::Entropy(getrandom::Error::UNSUPPORTED))
    );
}

#[test]
fn generation_failures_are_typed() {
    assert_eq!(
        SshKeyPair::generate_from(&mut FailingRandom)
            .unwrap_err()
            .kind(),
        KeysErrorKind::Entropy
    );
    assert_eq!(
        SshKeyPair::generate_from(&mut ZeroRandom),
        Err(KeysError::MaterialRejected(ModelError::InvalidSecret {
            kind: SecretKind::Ed25519Seed
        }))
    );
}

#[test]
fn generated_keys_are_distinct_and_rederivable() {
    let first = SshKeyPair::generate().unwrap();
    let second = SshKeyPair::generate().unwrap();
    assert_ne!(first.public(), second.public());
    assert_ne!(first.public().fingerprint(), second.public().fingerprint());
    let (seed, public) = first.clone().into_parts();
    assert_eq!(SshKeyPair::from_seed(seed).unwrap().public(), public);
}

#[test]
fn debug_never_shows_private_material() {
    let pair = SshKeyPair::generate().unwrap();
    let file = pair.openssh_private_key(&comment("ops@lon1")).unwrap();
    let seed_text = pair.seed().expose_text();
    let body_line = file.expose_pem().lines().nth(2).unwrap().to_owned();
    for debug in [format!("{pair:?}"), format!("{file:?}")] {
        assert!(!debug.contains(seed_text.as_str()), "{debug}");
        assert!(!debug.contains(&body_line), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}
