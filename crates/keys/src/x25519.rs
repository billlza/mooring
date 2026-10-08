// SPDX-License-Identifier: GPL-3.0-or-later

//! X25519 key pairs for REALITY and WireGuard (RFC 7748).
//!
//! Private keys are stored clamped, exactly as `xray x25519` (Xray v26.9.30
//! `main/commands/all/curve25519.go:51-53`) and `wg genkey` print them, so a
//! stored key and the engine's echo of it (`xray x25519 -i <key>`) agree.
//! The text encodings are the model's: REALITY keys are 43 characters of
//! unpadded base64url and WireGuard keys 44 characters of padded base64.

use mooring_model::secret::{RealityPrivateKey, WgPrivateKey};
use mooring_model::{WgKey, X25519Pub};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::KeysError;
use crate::random::{OsRandom, RandomSource, draw};

/// Clamps a scalar as RFC 7748 §5 `decodeScalar25519` does: clears the low
/// three bits and the top bit, and sets bit 254.
const fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 0b1111_1000;
    scalar[31] &= 0b0111_1111;
    scalar[31] |= 0b0100_0000;
}

/// `X25519(k, 9)`: the public key of the private scalar `k`.
///
/// `StaticSecret` clamps `k` itself, so a stored key need not be clamped;
/// the secret copy is zeroized when `secret` drops.
fn public_key(private: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    PublicKey::from(&secret).to_bytes()
}

macro_rules! x25519_key_pair {
    (
        $(#[$doc:meta])*
        $name:ident, $private:ident, $public:ident
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            private: $private,
            public: $public,
        }

        impl $name {
            /// Generates a fresh key pair from the operating system's random
            /// source, storing the private scalar clamped.
            pub fn generate() -> Result<Self, KeysError> {
                Self::generate_from(&mut OsRandom)
            }

            pub(crate) fn generate_from(source: &mut impl RandomSource) -> Result<Self, KeysError> {
                let mut scalar = draw::<32>(source)?;
                clamp(&mut scalar);
                let private = $private::from_bytes(*scalar).map_err(KeysError::MaterialRejected)?;
                Self::from_private(private)
            }

            /// Derives the public key of a stored private key.
            pub fn from_private(private: $private) -> Result<Self, KeysError> {
                let public = $public::from_bytes(public_key(private.expose_bytes()))
                    .map_err(KeysError::MaterialRejected)?;
                Ok(Self { private, public })
            }

            /// The private key.
            #[must_use]
            pub const fn private(&self) -> &$private {
                &self.private
            }

            /// The public key.
            #[must_use]
            pub const fn public(&self) -> $public {
                self.public
            }

            /// Splits the pair into its private and public keys.
            #[must_use]
            pub fn into_parts(self) -> ($private, $public) {
                (self.private, self.public)
            }
        }
    };
}

x25519_key_pair!(
    /// A node's REALITY key pair: Xray's `privateKey` and the clients'
    /// `public_key` (`password` in `xray x25519` output).
    RealityKeyPair,
    RealityPrivateKey,
    X25519Pub
);

x25519_key_pair!(
    /// One side of a node's WireGuard tunnel.
    WgKeyPair,
    WgPrivateKey,
    WgKey
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeysErrorKind;
    use crate::testing::{CountingRandom, FailingRandom, hex};
    use sha2::{Digest as _, Sha256};

    // RFC 7748 §6.1.
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_SECRET: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    fn is_clamped(scalar: &[u8; 32]) -> bool {
        scalar[0] & 0b0000_0111 == 0 && scalar[31] & 0b1100_0000 == 0b0100_0000
    }

    #[test]
    fn rfc7748_section_6_1_vectors() {
        let alice = RealityKeyPair::from_private(
            RealityPrivateKey::from_bytes(hex(ALICE_PRIVATE)).unwrap(),
        )
        .unwrap();
        assert_eq!(*alice.public().as_bytes(), hex::<32>(ALICE_PUBLIC));
        let bob =
            WgKeyPair::from_private(WgPrivateKey::from_bytes(hex(BOB_PRIVATE)).unwrap()).unwrap();
        assert_eq!(*bob.public().as_bytes(), hex::<32>(BOB_PUBLIC));

        // Each side's derived public key yields the RFC's shared secret.
        let alice_secret = StaticSecret::from(*alice.private().expose_bytes());
        let bob_secret = StaticSecret::from(*bob.private().expose_bytes());
        let alice_view = alice_secret.diffie_hellman(&PublicKey::from(*bob.public().as_bytes()));
        let bob_view = bob_secret.diffie_hellman(&PublicKey::from(*alice.public().as_bytes()));
        assert_eq!(*alice_view.as_bytes(), hex::<32>(SHARED_SECRET));
        assert_eq!(*bob_view.as_bytes(), hex::<32>(SHARED_SECRET));
    }

    #[test]
    fn rfc7748_alice_in_both_text_encodings() {
        let reality = RealityKeyPair::from_private(
            RealityPrivateKey::from_bytes(hex(ALICE_PRIVATE)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reality.public().to_string(),
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
        );
        let wg =
            WgKeyPair::from_private(WgPrivateKey::from_bytes(hex(ALICE_PRIVATE)).unwrap()).unwrap();
        assert_eq!(
            wg.public().to_string(),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
    }

    /// Independent vectors from OpenSSL 3.6.4 (the procedure documented in
    /// `crates/fixtures/src/material.rs`): the private scalar is the SHA-256
    /// of a label, clamped, and OpenSSL derived the public key.
    #[test]
    fn openssl_derived_vectors_match_generation_from_raw_bytes() {
        let raw: [u8; 32] = Sha256::digest(b"mooring-fixture/lon1/reality-private").into();
        let reality =
            RealityKeyPair::generate_from(&mut crate::testing::ReplayRandom::new(&raw)).unwrap();
        assert_eq!(
            *reality.private().expose_text(),
            "qAr2x8Vah8WO2JdHLUnMUUjqHpzO0vbDn7gKWAh17E8"
        );
        assert_eq!(
            reality.public().to_string(),
            "QEsWwS6uUzMjri07Ajw6HWWPRuUgAlPCkCstYBSWq18"
        );

        let raw: [u8; 32] = Sha256::digest(b"mooring-fixture/lon1/wg-vps-private").into();
        let wg = WgKeyPair::generate_from(&mut crate::testing::ReplayRandom::new(&raw)).unwrap();
        assert_eq!(
            *wg.private().expose_text(),
            "kLHtzcgJYSDaWc3YAUUTHdXc1hGsKcrarNmI8FlXGVg="
        );
        assert_eq!(
            wg.public().to_string(),
            "bNlQS933+LFbuy6C05O/HL03ezxdOUm0eMvwUDmokFk="
        );
    }

    #[test]
    fn generated_private_keys_are_stored_clamped() {
        // The draw breaks all three rules: the low three bits are set, the
        // top bit is set and bit 254 is clear.
        let mut raw = [0x11_u8; 32];
        raw[0] = 0xff;
        raw[31] = 0x80;
        let mut expected = [0x11_u8; 32];
        expected[0] = 0xf8;
        expected[31] = 0x40;
        let mut source = crate::testing::ReplayRandom::new(&[raw, raw].concat());
        let reality = RealityKeyPair::generate_from(&mut source).unwrap();
        let wg = WgKeyPair::generate_from(&mut source).unwrap();
        assert_eq!(*reality.private().expose_bytes(), expected);
        assert_eq!(*wg.private().expose_bytes(), expected);

        // Clamping before storage does not change the public key.
        let unclamped =
            RealityKeyPair::from_private(RealityPrivateKey::from_bytes(raw).unwrap()).unwrap();
        assert_eq!(unclamped.public(), reality.public());
    }

    #[test]
    fn os_generation_yields_distinct_clamped_keys() {
        let first = RealityKeyPair::generate().unwrap();
        let second = RealityKeyPair::generate().unwrap();
        assert_ne!(first.public(), second.public());
        assert!(is_clamped(first.private().expose_bytes()));
        assert_eq!(first.private().expose_text().len(), 43);
        assert_eq!(first.public().to_string().len(), 43);

        let wg = WgKeyPair::generate().unwrap();
        assert!(is_clamped(wg.private().expose_bytes()));
        assert_eq!(wg.private().expose_text().len(), 44);
        assert_eq!(wg.public().to_string().len(), 44);
        let (private, public) = wg.clone().into_parts();
        assert_eq!(WgKeyPair::from_private(private).unwrap().public(), public);
    }

    #[test]
    fn generation_derives_the_public_key_of_the_stored_scalar() {
        let pair = RealityKeyPair::generate_from(&mut CountingRandom::starting_at(1)).unwrap();
        let mut expected: [u8; 32] = std::array::from_fn(|index| u8::try_from(index + 1).unwrap());
        clamp(&mut expected);
        assert_eq!(*pair.private().expose_bytes(), expected);
        assert_eq!(*pair.public().as_bytes(), public_key(&expected));
    }

    #[test]
    fn entropy_failure_is_reported() {
        assert_eq!(
            RealityKeyPair::generate_from(&mut FailingRandom)
                .unwrap_err()
                .kind(),
            KeysErrorKind::Entropy
        );
        assert_eq!(
            WgKeyPair::generate_from(&mut FailingRandom)
                .unwrap_err()
                .kind(),
            KeysErrorKind::Entropy
        );
    }

    #[test]
    fn debug_never_shows_the_private_key() {
        let pair = RealityKeyPair::generate().unwrap();
        let debug = format!("{pair:?}");
        assert!(!debug.contains(pair.private().expose_text().as_str()));
        assert!(debug.contains("<redacted>"));
    }
}
