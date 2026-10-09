// SPDX-License-Identifier: GPL-3.0-or-later

//! Secrets (design §7, §12): the `Secret<T>` wrapper, the typed secret
//! materials, `SecretRef` and the in-memory `SecretSnapshot`.
//!
//! No type here implements `Serialize` or `Display`, so no secret can reach
//! `state.json` or a log line by accident: the state types derive
//! `Serialize`, which would not compile with a secret field.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cert::{PemLabel, pem_decode, pem_encode};
use crate::encoding::{decode_b64std_32, decode_b64url_32, encode_b64std, encode_b64url};
use crate::error::ModelError;
use crate::ids::{NodeId, UserId, Uuid};
use crate::kinds;
use crate::ports::ListenerIdx;

/// A value that is zeroized on drop, redacted in `Debug`, and has neither
/// `Display` nor `Serialize`.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Takes ownership of `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrows the secret value; every use site is an explicit exposure.
    #[must_use]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq> Eq for Secret<T> {}

kinds! {
    /// The kind of secret material a `SecretRef` names.
    pub enum SecretKind {
        /// A REALITY X25519 private key.
        RealityPrivateKey,
        /// A WireGuard private key.
        WgPrivateKey,
        /// The Hysteria2 certificate's PKCS#8 private key.
        Hy2PrivateKey,
        /// A Hysteria2 password or salamander obfuscation password.
        Password,
        /// A VLESS or loopback credential UUID.
        Uuid,
        /// An Ed25519 private key seed.
        Ed25519Seed,
    }
}

fn invalid(kind: SecretKind) -> ModelError {
    ModelError::InvalidSecret { kind }
}

macro_rules! secret_key_32 {
    (
        $(#[$doc:meta])*
        $name:ident, $kind:expr, $decode:path, $encode:path, $text:literal
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(Secret<[u8; 32]>);

        impl $name {
            /// Accepts 32 bytes unless they are all zero, which would mean a
            /// broken entropy source.
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ModelError> {
                if bytes == [0; 32] {
                    Err(invalid($kind))
                } else {
                    Ok(Self(Secret::new(bytes)))
                }
            }

            #[doc = concat!("Parses ", $text, ".")]
            pub fn parse(text: &str) -> Result<Self, ModelError> {
                let bytes = $decode(text).ok_or_else(|| invalid($kind))?;
                Self::from_bytes(*bytes)
            }

            /// Borrows the raw bytes.
            #[must_use]
            pub const fn expose_bytes(&self) -> &[u8; 32] {
                self.0.expose_secret()
            }

            #[doc = concat!("The canonical text, ", $text, ", in a zeroizing buffer.")]
            #[must_use]
            pub fn expose_text(&self) -> Zeroizing<String> {
                $encode(self.0.expose_secret())
            }
        }
    };
}

secret_key_32!(
    /// A REALITY X25519 private key (Xray `privateKey`).
    RealityPrivateKey,
    SecretKind::RealityPrivateKey,
    decode_b64url_32,
    encode_b64url,
    "43 characters of unpadded base64url"
);

secret_key_32!(
    /// A WireGuard private key.
    WgPrivateKey,
    SecretKind::WgPrivateKey,
    decode_b64std_32,
    encode_b64std,
    "44 characters of padded standard base64"
);

secret_key_32!(
    /// An Ed25519 private key seed (the one-time SSH bootstrap key).
    Ed25519Seed,
    SecretKind::Ed25519Seed,
    decode_b64std_32,
    encode_b64std,
    "44 characters of padded standard base64"
);

secret_key_32!(
    /// A Hysteria2 user password or salamander password: 32 random bytes
    /// whose base64url text is the password itself.
    Password,
    SecretKind::Password,
    decode_b64url_32,
    encode_b64url,
    "43 characters of unpadded base64url"
);

/// The Hysteria2 certificate key: one canonical unencrypted PKCS#8
/// `PRIVATE KEY` PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2KeyPem(Secret<String>);

impl Hy2KeyPem {
    /// Accepts one canonical `PRIVATE KEY` PEM block.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        pem_decode(PemLabel::PrivateKey, text).map_err(|_| invalid(SecretKind::Hy2PrivateKey))?;
        Ok(Self(Secret::new(text.to_owned())))
    }

    /// Wraps non-empty PKCS#8 DER bytes in a canonical PEM block.
    pub fn from_der(der: &[u8]) -> Result<Self, ModelError> {
        if der.is_empty() {
            return Err(invalid(SecretKind::Hy2PrivateKey));
        }
        let text = pem_encode(PemLabel::PrivateKey, der);
        Ok(Self(Secret::new(text.to_string())))
    }

    /// Borrows the PEM text.
    #[must_use]
    pub fn expose_pem(&self) -> &str {
        self.0.expose_secret()
    }

    /// The PEM lines without line endings, as sing-box's `key` list takes them.
    pub fn expose_lines(&self) -> std::str::Lines<'_> {
        self.0.expose_secret().lines()
    }

    /// The base64 body lines (the secret part), each in a zeroizing buffer.
    fn body_lines(&self) -> impl Iterator<Item = Zeroizing<String>> {
        self.expose_lines()
            .filter(|line| !line.starts_with("-----"))
            .map(|line| Zeroizing::new(line.to_owned()))
    }
}

/// One piece of secret material of any kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretMaterial {
    /// See [`RealityPrivateKey`].
    RealityPrivateKey(RealityPrivateKey),
    /// See [`WgPrivateKey`].
    WgPrivateKey(WgPrivateKey),
    /// See [`Hy2KeyPem`].
    Hy2PrivateKey(Hy2KeyPem),
    /// See [`Password`].
    Password(Password),
    /// A credential UUID.
    Uuid(Secret<Uuid>),
    /// See [`Ed25519Seed`].
    Ed25519Seed(Ed25519Seed),
}

impl SecretMaterial {
    /// The kind of this material.
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        match self {
            Self::RealityPrivateKey(_) => SecretKind::RealityPrivateKey,
            Self::WgPrivateKey(_) => SecretKind::WgPrivateKey,
            Self::Hy2PrivateKey(_) => SecretKind::Hy2PrivateKey,
            Self::Password(_) => SecretKind::Password,
            Self::Uuid(_) => SecretKind::Uuid,
            Self::Ed25519Seed(_) => SecretKind::Ed25519Seed,
        }
    }

    /// Parses the canonical text of a material of `kind` (the keychain item format).
    pub fn decode(kind: SecretKind, text: &str) -> Result<Self, ModelError> {
        Ok(match kind {
            SecretKind::RealityPrivateKey => {
                Self::RealityPrivateKey(RealityPrivateKey::parse(text)?)
            }
            SecretKind::WgPrivateKey => Self::WgPrivateKey(WgPrivateKey::parse(text)?),
            SecretKind::Hy2PrivateKey => Self::Hy2PrivateKey(Hy2KeyPem::parse(text)?),
            SecretKind::Password => Self::Password(Password::parse(text)?),
            SecretKind::Uuid => Self::Uuid(Secret::new(
                Uuid::parse(text).map_err(|_| invalid(SecretKind::Uuid))?,
            )),
            SecretKind::Ed25519Seed => Self::Ed25519Seed(Ed25519Seed::parse(text)?),
        })
    }

    /// The canonical text of the material (the keychain item format).
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        match self {
            Self::RealityPrivateKey(key) => key.expose_text(),
            Self::WgPrivateKey(key) => key.expose_text(),
            Self::Hy2PrivateKey(key) => Zeroizing::new(key.expose_pem().to_owned()),
            Self::Password(password) => password.expose_text(),
            Self::Uuid(uuid) => uuid.expose_secret().to_hyphenated(),
            Self::Ed25519Seed(seed) => seed.expose_text(),
        }
    }

    /// Every text form in which this material can appear in rendered configs
    /// or engine output, for exact-substring scrubbing (design §12).
    #[must_use]
    pub fn needles(&self) -> Vec<Zeroizing<String>> {
        match self {
            Self::Hy2PrivateKey(key) => key.body_lines().collect(),
            Self::RealityPrivateKey(_)
            | Self::WgPrivateKey(_)
            | Self::Password(_)
            | Self::Uuid(_)
            | Self::Ed25519Seed(_) => vec![self.encode()],
        }
    }
}

/// Names one keychain item (design §7). Every reference but one belongs to
/// a node ([`SecretRef::node`]); the deployment's ntfy topic belongs to no
/// node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretRef {
    /// The deployment's one ntfy topic (design §15.8, decision F6): the
    /// operator's phone subscribes to it, and every channel node sends its
    /// notices to it, so it is referenced while at least one node has its
    /// alert channels set up, and is replaced only through a change that
    /// leaves none (design §12). `Password` material, 32 random bytes
    /// whose 43 base64url characters are the topic name, above F6's 128
    /// bits. That those characters fit ntfy's topic rule
    /// (`[-_A-Za-z0-9]{1,64}`) is an inference from ntfy's server source,
    /// checked in M4.
    AlertTopic,
    /// The node's REALITY private key.
    NodeRealityPrivate(NodeId),
    /// The VPS side of the node's WireGuard tunnel.
    NodeWgVpsPrivate(NodeId),
    /// The Mac side of the node's WireGuard tunnel.
    NodeWgMacPrivate(NodeId),
    /// The node's Hysteria2 certificate key.
    NodeHy2Key(NodeId),
    /// The salamander password of one Hysteria2 listener.
    NodeHy2Obfs(NodeId, ListenerIdx),
    /// The one-time SSH bootstrap key, deleted at adoption.
    NodeSshBootstrapPrivate(NodeId),
    /// The UUID of the node's own Healthchecks check, the one its ping URL
    /// ends in (design §15.8, decision F6). Healthchecks issues version-4
    /// UUIDs (an inference from its source, checked in M4); any other form
    /// is refused as `InvalidSecret`, never accepted some other way.
    NodeDeadManCheck(NodeId),
    /// The UUID of the node's Healthchecks check that is pinged while the
    /// Mac's handshake is fresh (`MacAlive`, design §15.8, decision F6).
    NodeMacAliveCheck(NodeId),
    /// A user's VLESS UUID on one node.
    UserVlessUuid(UserId, NodeId),
    /// A user's Hysteria2 password on one node.
    UserHy2Password(UserId, NodeId),
    /// A user's loopback VLESS UUID (Hysteria2 handoff) on one node.
    UserLoopUuid(UserId, NodeId),
    /// The probe identity's VLESS UUID on one node.
    ProbeVlessUuid(NodeId),
    /// The probe identity's Hysteria2 password on one node.
    ProbeHy2Password(NodeId),
    /// The probe identity's loopback VLESS UUID on one node.
    ProbeLoopUuid(NodeId),
}

impl SecretRef {
    /// The kind of material this reference names.
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        match self {
            Self::NodeRealityPrivate(_) => SecretKind::RealityPrivateKey,
            Self::NodeWgVpsPrivate(_) | Self::NodeWgMacPrivate(_) => SecretKind::WgPrivateKey,
            Self::NodeHy2Key(_) => SecretKind::Hy2PrivateKey,
            Self::AlertTopic
            | Self::NodeHy2Obfs(..)
            | Self::UserHy2Password(..)
            | Self::ProbeHy2Password(_) => SecretKind::Password,
            Self::NodeSshBootstrapPrivate(_) => SecretKind::Ed25519Seed,
            Self::NodeDeadManCheck(_)
            | Self::NodeMacAliveCheck(_)
            | Self::UserVlessUuid(..)
            | Self::UserLoopUuid(..)
            | Self::ProbeVlessUuid(_)
            | Self::ProbeLoopUuid(_) => SecretKind::Uuid,
        }
    }

    /// The node this secret belongs to, or `None` for the one that
    /// belongs to no node: the deployment's ntfy topic
    /// ([`SecretRef::AlertTopic`]).
    #[must_use]
    pub const fn node(&self) -> Option<&NodeId> {
        match self {
            Self::AlertTopic => None,
            Self::NodeRealityPrivate(node)
            | Self::NodeWgVpsPrivate(node)
            | Self::NodeWgMacPrivate(node)
            | Self::NodeHy2Key(node)
            | Self::NodeHy2Obfs(node, _)
            | Self::NodeSshBootstrapPrivate(node)
            | Self::NodeDeadManCheck(node)
            | Self::NodeMacAliveCheck(node)
            | Self::UserVlessUuid(_, node)
            | Self::UserHy2Password(_, node)
            | Self::UserLoopUuid(_, node)
            | Self::ProbeVlessUuid(node)
            | Self::ProbeHy2Password(node)
            | Self::ProbeLoopUuid(node) => Some(node),
        }
    }
}

/// The stable text form, used as the keychain account name:
/// `alert/topic` for the deployment's ntfy topic, `node/<node>/<item>`
/// (a channel node's checks included: `node/<node>/dead-man-check`,
/// `node/<node>/mac-alive-check`), `node/<node>/hy2-obfs/<listener>`,
/// `user/<user>/<node>/<item>` or `probe/<node>/<item>`.
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlertTopic => f.write_str("alert/topic"),
            Self::NodeRealityPrivate(node) => write!(f, "node/{node}/reality-private"),
            Self::NodeWgVpsPrivate(node) => write!(f, "node/{node}/wg-vps-private"),
            Self::NodeWgMacPrivate(node) => write!(f, "node/{node}/wg-mac-private"),
            Self::NodeHy2Key(node) => write!(f, "node/{node}/hy2-key"),
            Self::NodeHy2Obfs(node, listener) => write!(f, "node/{node}/hy2-obfs/{listener}"),
            Self::NodeSshBootstrapPrivate(node) => write!(f, "node/{node}/ssh-bootstrap-private"),
            Self::NodeDeadManCheck(node) => write!(f, "node/{node}/dead-man-check"),
            Self::NodeMacAliveCheck(node) => write!(f, "node/{node}/mac-alive-check"),
            Self::UserVlessUuid(user, node) => write!(f, "user/{user}/{node}/vless-uuid"),
            Self::UserHy2Password(user, node) => write!(f, "user/{user}/{node}/hy2-password"),
            Self::UserLoopUuid(user, node) => write!(f, "user/{user}/{node}/loop-uuid"),
            Self::ProbeVlessUuid(node) => write!(f, "probe/{node}/vless-uuid"),
            Self::ProbeHy2Password(node) => write!(f, "probe/{node}/hy2-password"),
            Self::ProbeLoopUuid(node) => write!(f, "probe/{node}/loop-uuid"),
        }
    }
}

impl FromStr for SecretRef {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = text.split('/').collect();
        let node = |text: &str| NodeId::parse(text).map_err(|_| ModelError::InvalidSecretRef);
        let user = |text: &str| UserId::parse(text).map_err(|_| ModelError::InvalidSecretRef);
        match parts.as_slice() {
            ["alert", "topic"] => Ok(Self::AlertTopic),
            ["node", n, "reality-private"] => Ok(Self::NodeRealityPrivate(node(n)?)),
            ["node", n, "wg-vps-private"] => Ok(Self::NodeWgVpsPrivate(node(n)?)),
            ["node", n, "wg-mac-private"] => Ok(Self::NodeWgMacPrivate(node(n)?)),
            ["node", n, "hy2-key"] => Ok(Self::NodeHy2Key(node(n)?)),
            ["node", n, "hy2-obfs", index] => {
                let index = parse_listener(index)?;
                Ok(Self::NodeHy2Obfs(node(n)?, index))
            }
            ["node", n, "ssh-bootstrap-private"] => Ok(Self::NodeSshBootstrapPrivate(node(n)?)),
            ["node", n, "dead-man-check"] => Ok(Self::NodeDeadManCheck(node(n)?)),
            ["node", n, "mac-alive-check"] => Ok(Self::NodeMacAliveCheck(node(n)?)),
            ["user", u, n, "vless-uuid"] => Ok(Self::UserVlessUuid(user(u)?, node(n)?)),
            ["user", u, n, "hy2-password"] => Ok(Self::UserHy2Password(user(u)?, node(n)?)),
            ["user", u, n, "loop-uuid"] => Ok(Self::UserLoopUuid(user(u)?, node(n)?)),
            ["probe", n, "vless-uuid"] => Ok(Self::ProbeVlessUuid(node(n)?)),
            ["probe", n, "hy2-password"] => Ok(Self::ProbeHy2Password(node(n)?)),
            ["probe", n, "loop-uuid"] => Ok(Self::ProbeLoopUuid(node(n)?)),
            _ => Err(ModelError::InvalidSecretRef),
        }
    }
}

/// The material's kind differs from the kind its reference names.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("secret {secret_ref} expects {expected} material, got {found}")]
pub struct SecretKindMismatch {
    /// The reference.
    pub secret_ref: SecretRef,
    /// The kind the reference names.
    pub expected: SecretKind,
    /// The kind of the material supplied.
    pub found: SecretKind,
}

/// One secret together with the reference it is stored under.
///
/// Each variant names one [`SecretRef`] variant and holds the material type
/// that reference names, so a material of the wrong kind cannot be paired
/// with a reference: [`SecretEntry::new`] is the one place the kinds are
/// compared, for material read back as an untyped [`SecretMaterial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretEntry {
    /// See [`SecretRef::AlertTopic`].
    AlertTopic(Password),
    /// See [`SecretRef::NodeRealityPrivate`].
    NodeRealityPrivate(NodeId, RealityPrivateKey),
    /// See [`SecretRef::NodeWgVpsPrivate`].
    NodeWgVpsPrivate(NodeId, WgPrivateKey),
    /// See [`SecretRef::NodeWgMacPrivate`].
    NodeWgMacPrivate(NodeId, WgPrivateKey),
    /// See [`SecretRef::NodeHy2Key`].
    NodeHy2Key(NodeId, Hy2KeyPem),
    /// See [`SecretRef::NodeHy2Obfs`].
    NodeHy2Obfs(NodeId, ListenerIdx, Password),
    /// See [`SecretRef::NodeSshBootstrapPrivate`].
    NodeSshBootstrapPrivate(NodeId, Ed25519Seed),
    /// See [`SecretRef::NodeDeadManCheck`].
    NodeDeadManCheck(NodeId, Secret<Uuid>),
    /// See [`SecretRef::NodeMacAliveCheck`].
    NodeMacAliveCheck(NodeId, Secret<Uuid>),
    /// See [`SecretRef::UserVlessUuid`].
    UserVlessUuid(UserId, NodeId, Secret<Uuid>),
    /// See [`SecretRef::UserHy2Password`].
    UserHy2Password(UserId, NodeId, Password),
    /// See [`SecretRef::UserLoopUuid`].
    UserLoopUuid(UserId, NodeId, Secret<Uuid>),
    /// See [`SecretRef::ProbeVlessUuid`].
    ProbeVlessUuid(NodeId, Secret<Uuid>),
    /// See [`SecretRef::ProbeHy2Password`].
    ProbeHy2Password(NodeId, Password),
    /// See [`SecretRef::ProbeLoopUuid`].
    ProbeLoopUuid(NodeId, Secret<Uuid>),
}

impl SecretEntry {
    /// Pairs `material` with `secret_ref` if the material is of the kind
    /// the reference names.
    pub fn new(
        secret_ref: SecretRef,
        material: SecretMaterial,
    ) -> Result<Self, SecretKindMismatch> {
        use SecretMaterial as M;
        use SecretRef as R;
        let expected = secret_ref.kind();
        let found = material.kind();
        Ok(match (secret_ref, material) {
            (R::AlertTopic, M::Password(topic)) => Self::AlertTopic(topic),
            (R::NodeRealityPrivate(node), M::RealityPrivateKey(key)) => {
                Self::NodeRealityPrivate(node, key)
            }
            (R::NodeWgVpsPrivate(node), M::WgPrivateKey(key)) => Self::NodeWgVpsPrivate(node, key),
            (R::NodeWgMacPrivate(node), M::WgPrivateKey(key)) => Self::NodeWgMacPrivate(node, key),
            (R::NodeHy2Key(node), M::Hy2PrivateKey(key)) => Self::NodeHy2Key(node, key),
            (R::NodeHy2Obfs(node, listener), M::Password(password)) => {
                Self::NodeHy2Obfs(node, listener, password)
            }
            (R::NodeSshBootstrapPrivate(node), M::Ed25519Seed(seed)) => {
                Self::NodeSshBootstrapPrivate(node, seed)
            }
            (R::NodeDeadManCheck(node), M::Uuid(uuid)) => Self::NodeDeadManCheck(node, uuid),
            (R::NodeMacAliveCheck(node), M::Uuid(uuid)) => Self::NodeMacAliveCheck(node, uuid),
            (R::UserVlessUuid(user, node), M::Uuid(uuid)) => Self::UserVlessUuid(user, node, uuid),
            (R::UserHy2Password(user, node), M::Password(password)) => {
                Self::UserHy2Password(user, node, password)
            }
            (R::UserLoopUuid(user, node), M::Uuid(uuid)) => Self::UserLoopUuid(user, node, uuid),
            (R::ProbeVlessUuid(node), M::Uuid(uuid)) => Self::ProbeVlessUuid(node, uuid),
            (R::ProbeHy2Password(node), M::Password(password)) => {
                Self::ProbeHy2Password(node, password)
            }
            (R::ProbeLoopUuid(node), M::Uuid(uuid)) => Self::ProbeLoopUuid(node, uuid),
            (secret_ref, _) => {
                return Err(SecretKindMismatch {
                    secret_ref,
                    expected,
                    found,
                });
            }
        })
    }

    /// The reference the material is stored under.
    #[must_use]
    pub fn secret_ref(&self) -> SecretRef {
        match self {
            Self::AlertTopic(_) => SecretRef::AlertTopic,
            Self::NodeRealityPrivate(node, _) => SecretRef::NodeRealityPrivate(node.clone()),
            Self::NodeWgVpsPrivate(node, _) => SecretRef::NodeWgVpsPrivate(node.clone()),
            Self::NodeWgMacPrivate(node, _) => SecretRef::NodeWgMacPrivate(node.clone()),
            Self::NodeHy2Key(node, _) => SecretRef::NodeHy2Key(node.clone()),
            Self::NodeHy2Obfs(node, listener, _) => SecretRef::NodeHy2Obfs(node.clone(), *listener),
            Self::NodeSshBootstrapPrivate(node, _) => {
                SecretRef::NodeSshBootstrapPrivate(node.clone())
            }
            Self::NodeDeadManCheck(node, _) => SecretRef::NodeDeadManCheck(node.clone()),
            Self::NodeMacAliveCheck(node, _) => SecretRef::NodeMacAliveCheck(node.clone()),
            Self::UserVlessUuid(user, node, _) => {
                SecretRef::UserVlessUuid(user.clone(), node.clone())
            }
            Self::UserHy2Password(user, node, _) => {
                SecretRef::UserHy2Password(user.clone(), node.clone())
            }
            Self::UserLoopUuid(user, node, _) => {
                SecretRef::UserLoopUuid(user.clone(), node.clone())
            }
            Self::ProbeVlessUuid(node, _) => SecretRef::ProbeVlessUuid(node.clone()),
            Self::ProbeHy2Password(node, _) => SecretRef::ProbeHy2Password(node.clone()),
            Self::ProbeLoopUuid(node, _) => SecretRef::ProbeLoopUuid(node.clone()),
        }
    }

    /// Splits the entry into its reference and its untyped material.
    #[must_use]
    pub fn into_parts(self) -> (SecretRef, SecretMaterial) {
        let secret_ref = self.secret_ref();
        let material = match self {
            Self::NodeRealityPrivate(_, key) => SecretMaterial::RealityPrivateKey(key),
            Self::NodeWgVpsPrivate(_, key) | Self::NodeWgMacPrivate(_, key) => {
                SecretMaterial::WgPrivateKey(key)
            }
            Self::NodeHy2Key(_, key) => SecretMaterial::Hy2PrivateKey(key),
            Self::AlertTopic(password)
            | Self::NodeHy2Obfs(_, _, password)
            | Self::UserHy2Password(_, _, password)
            | Self::ProbeHy2Password(_, password) => SecretMaterial::Password(password),
            Self::NodeSshBootstrapPrivate(_, seed) => SecretMaterial::Ed25519Seed(seed),
            Self::NodeDeadManCheck(_, uuid)
            | Self::NodeMacAliveCheck(_, uuid)
            | Self::UserVlessUuid(_, _, uuid)
            | Self::UserLoopUuid(_, _, uuid)
            | Self::ProbeVlessUuid(_, uuid)
            | Self::ProbeLoopUuid(_, uuid) => SecretMaterial::Uuid(uuid),
        };
        (secret_ref, material)
    }
}

/// Parses a listener index written without sign or leading zeros.
fn parse_listener(text: &str) -> Result<ListenerIdx, ModelError> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(ModelError::InvalidSecretRef);
    }
    text.parse::<u8>()
        .map(ListenerIdx::new)
        .map_err(|_| ModelError::InvalidSecretRef)
}

/// A secret snapshot lookup or insertion failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretSnapshotError {
    /// The snapshot holds no material for the reference.
    #[error("secret {secret_ref} is missing")]
    Missing {
        /// The missing reference.
        secret_ref: SecretRef,
    },
    /// The snapshot already holds material for the reference.
    #[error("secret {secret_ref} is already present")]
    Duplicate {
        /// The duplicated reference.
        secret_ref: SecretRef,
    },
}

kinds! {
    /// The kind of a [`SecretSnapshotError`], without its details.
    pub enum SecretSnapshotErrorKind {
        /// See [`SecretSnapshotError::Missing`].
        Missing,
        /// See [`SecretSnapshotError::Duplicate`].
        Duplicate,
    }
}

impl SecretSnapshotError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> SecretSnapshotErrorKind {
        match self {
            Self::Missing { .. } => SecretSnapshotErrorKind::Missing,
            Self::Duplicate { .. } => SecretSnapshotErrorKind::Duplicate,
        }
    }
}

fn insert_new<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    secret_ref: SecretRef,
) -> Result<(), SecretSnapshotError> {
    match map.entry(key) {
        std::collections::btree_map::Entry::Occupied(_) => {
            Err(SecretSnapshotError::Duplicate { secret_ref })
        }
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(value);
            Ok(())
        }
    }
}

/// Fills `slot`, which holds the one secret of its reference, if it is
/// empty (`Duplicate` otherwise, keeping the first value).
fn insert_once<V>(
    slot: &mut Option<V>,
    value: V,
    secret_ref: SecretRef,
) -> Result<(), SecretSnapshotError> {
    if slot.is_some() {
        return Err(SecretSnapshotError::Duplicate { secret_ref });
    }
    *slot = Some(value);
    Ok(())
}

fn lookup<'a, K: Ord, V>(
    map: &'a BTreeMap<K, V>,
    key: &K,
    secret_ref: impl FnOnce() -> SecretRef,
) -> Result<&'a V, SecretSnapshotError> {
    map.get(key).ok_or_else(|| SecretSnapshotError::Missing {
        secret_ref: secret_ref(),
    })
}

/// The secrets of one configuration generation, held in memory.
///
/// Each secret kind has its own typed map, so a lookup can only fail with
/// `Missing`; a [`SecretEntry`] always pairs a reference with material of
/// its kind, so insertion can only fail with `Duplicate`.
#[derive(Debug, Default)]
pub struct SecretSnapshot {
    alert_topic: Option<Password>,
    reality: BTreeMap<NodeId, RealityPrivateKey>,
    wg_vps: BTreeMap<NodeId, WgPrivateKey>,
    wg_mac: BTreeMap<NodeId, WgPrivateKey>,
    hy2_key: BTreeMap<NodeId, Hy2KeyPem>,
    hy2_obfs: BTreeMap<(NodeId, ListenerIdx), Password>,
    ssh_bootstrap: BTreeMap<NodeId, Ed25519Seed>,
    dead_man_check: BTreeMap<NodeId, Secret<Uuid>>,
    mac_alive_check: BTreeMap<NodeId, Secret<Uuid>>,
    user_vless: BTreeMap<(UserId, NodeId), Secret<Uuid>>,
    user_hy2: BTreeMap<(UserId, NodeId), Password>,
    user_loop: BTreeMap<(UserId, NodeId), Secret<Uuid>>,
    probe_vless: BTreeMap<NodeId, Secret<Uuid>>,
    probe_hy2: BTreeMap<NodeId, Password>,
    probe_loop: BTreeMap<NodeId, Secret<Uuid>>,
}

impl SecretSnapshot {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `entry`; its reference must be new.
    pub fn insert(&mut self, entry: SecretEntry) -> Result<(), SecretSnapshotError> {
        use SecretEntry as E;
        let reference = entry.secret_ref();
        match entry {
            E::AlertTopic(topic) => insert_once(&mut self.alert_topic, topic, reference),
            E::NodeRealityPrivate(node, key) => insert_new(&mut self.reality, node, key, reference),
            E::NodeWgVpsPrivate(node, key) => insert_new(&mut self.wg_vps, node, key, reference),
            E::NodeWgMacPrivate(node, key) => insert_new(&mut self.wg_mac, node, key, reference),
            E::NodeHy2Key(node, key) => insert_new(&mut self.hy2_key, node, key, reference),
            E::NodeHy2Obfs(node, listener, password) => {
                insert_new(&mut self.hy2_obfs, (node, listener), password, reference)
            }
            E::NodeSshBootstrapPrivate(node, seed) => {
                insert_new(&mut self.ssh_bootstrap, node, seed, reference)
            }
            E::NodeDeadManCheck(node, uuid) => {
                insert_new(&mut self.dead_man_check, node, uuid, reference)
            }
            E::NodeMacAliveCheck(node, uuid) => {
                insert_new(&mut self.mac_alive_check, node, uuid, reference)
            }
            E::UserVlessUuid(user, node, uuid) => {
                insert_new(&mut self.user_vless, (user, node), uuid, reference)
            }
            E::UserHy2Password(user, node, password) => {
                insert_new(&mut self.user_hy2, (user, node), password, reference)
            }
            E::UserLoopUuid(user, node, uuid) => {
                insert_new(&mut self.user_loop, (user, node), uuid, reference)
            }
            E::ProbeVlessUuid(node, uuid) => {
                insert_new(&mut self.probe_vless, node, uuid, reference)
            }
            E::ProbeHy2Password(node, password) => {
                insert_new(&mut self.probe_hy2, node, password, reference)
            }
            E::ProbeLoopUuid(node, uuid) => insert_new(&mut self.probe_loop, node, uuid, reference),
        }
    }

    /// The node's REALITY private key.
    pub fn reality_private(
        &self,
        node: &NodeId,
    ) -> Result<&RealityPrivateKey, SecretSnapshotError> {
        lookup(&self.reality, node, || {
            SecretRef::NodeRealityPrivate(node.clone())
        })
    }

    /// The VPS side of the node's WireGuard key pair.
    pub fn wg_vps_private(&self, node: &NodeId) -> Result<&WgPrivateKey, SecretSnapshotError> {
        lookup(&self.wg_vps, node, || {
            SecretRef::NodeWgVpsPrivate(node.clone())
        })
    }

    /// The Mac side of the node's WireGuard key pair.
    pub fn wg_mac_private(&self, node: &NodeId) -> Result<&WgPrivateKey, SecretSnapshotError> {
        lookup(&self.wg_mac, node, || {
            SecretRef::NodeWgMacPrivate(node.clone())
        })
    }

    /// The node's Hysteria2 certificate key.
    pub fn hy2_key(&self, node: &NodeId) -> Result<&Hy2KeyPem, SecretSnapshotError> {
        lookup(&self.hy2_key, node, || SecretRef::NodeHy2Key(node.clone()))
    }

    /// The salamander password of one listener.
    pub fn hy2_obfs(
        &self,
        node: &NodeId,
        listener: ListenerIdx,
    ) -> Result<&Password, SecretSnapshotError> {
        lookup(&self.hy2_obfs, &(node.clone(), listener), || {
            SecretRef::NodeHy2Obfs(node.clone(), listener)
        })
    }

    /// The node's one-time SSH bootstrap key.
    pub fn ssh_bootstrap(&self, node: &NodeId) -> Result<&Ed25519Seed, SecretSnapshotError> {
        lookup(&self.ssh_bootstrap, node, || {
            SecretRef::NodeSshBootstrapPrivate(node.clone())
        })
    }

    /// The deployment's ntfy topic.
    pub fn alert_topic(&self) -> Result<&Password, SecretSnapshotError> {
        self.alert_topic
            .as_ref()
            .ok_or(SecretSnapshotError::Missing {
                secret_ref: SecretRef::AlertTopic,
            })
    }

    /// The UUID of the node's own Healthchecks check.
    pub fn dead_man_check(&self, node: &NodeId) -> Result<&Secret<Uuid>, SecretSnapshotError> {
        lookup(&self.dead_man_check, node, || {
            SecretRef::NodeDeadManCheck(node.clone())
        })
    }

    /// The UUID of the node's `MacAlive` Healthchecks check.
    pub fn mac_alive_check(&self, node: &NodeId) -> Result<&Secret<Uuid>, SecretSnapshotError> {
        lookup(&self.mac_alive_check, node, || {
            SecretRef::NodeMacAliveCheck(node.clone())
        })
    }

    /// A user's VLESS UUID on a node.
    pub fn user_vless_uuid(
        &self,
        user: &UserId,
        node: &NodeId,
    ) -> Result<&Secret<Uuid>, SecretSnapshotError> {
        lookup(&self.user_vless, &(user.clone(), node.clone()), || {
            SecretRef::UserVlessUuid(user.clone(), node.clone())
        })
    }

    /// A user's Hysteria2 password on a node.
    pub fn user_hy2_password(
        &self,
        user: &UserId,
        node: &NodeId,
    ) -> Result<&Password, SecretSnapshotError> {
        lookup(&self.user_hy2, &(user.clone(), node.clone()), || {
            SecretRef::UserHy2Password(user.clone(), node.clone())
        })
    }

    /// A user's loopback UUID on a node.
    pub fn user_loop_uuid(
        &self,
        user: &UserId,
        node: &NodeId,
    ) -> Result<&Secret<Uuid>, SecretSnapshotError> {
        lookup(&self.user_loop, &(user.clone(), node.clone()), || {
            SecretRef::UserLoopUuid(user.clone(), node.clone())
        })
    }

    /// The probe identity's VLESS UUID on a node.
    pub fn probe_vless_uuid(&self, node: &NodeId) -> Result<&Secret<Uuid>, SecretSnapshotError> {
        lookup(&self.probe_vless, node, || {
            SecretRef::ProbeVlessUuid(node.clone())
        })
    }

    /// The probe identity's Hysteria2 password on a node.
    pub fn probe_hy2_password(&self, node: &NodeId) -> Result<&Password, SecretSnapshotError> {
        lookup(&self.probe_hy2, node, || {
            SecretRef::ProbeHy2Password(node.clone())
        })
    }

    /// The probe identity's loopback UUID on a node.
    pub fn probe_loop_uuid(&self, node: &NodeId) -> Result<&Secret<Uuid>, SecretSnapshotError> {
        lookup(&self.probe_loop, node, || {
            SecretRef::ProbeLoopUuid(node.clone())
        })
    }

    /// Every reference held, in ascending order.
    #[must_use]
    pub fn refs(&self) -> Vec<SecretRef> {
        let mut refs: Vec<SecretRef> = Vec::with_capacity(self.len());
        refs.extend(self.alert_topic.iter().map(|_| SecretRef::AlertTopic));
        refs.extend(
            self.reality
                .keys()
                .cloned()
                .map(SecretRef::NodeRealityPrivate),
        );
        refs.extend(self.wg_vps.keys().cloned().map(SecretRef::NodeWgVpsPrivate));
        refs.extend(self.wg_mac.keys().cloned().map(SecretRef::NodeWgMacPrivate));
        refs.extend(self.hy2_key.keys().cloned().map(SecretRef::NodeHy2Key));
        refs.extend(
            self.hy2_obfs
                .keys()
                .map(|(node, listener)| SecretRef::NodeHy2Obfs(node.clone(), *listener)),
        );
        refs.extend(
            self.ssh_bootstrap
                .keys()
                .cloned()
                .map(SecretRef::NodeSshBootstrapPrivate),
        );
        refs.extend(
            self.dead_man_check
                .keys()
                .cloned()
                .map(SecretRef::NodeDeadManCheck),
        );
        refs.extend(
            self.mac_alive_check
                .keys()
                .cloned()
                .map(SecretRef::NodeMacAliveCheck),
        );
        refs.extend(
            self.user_vless
                .keys()
                .map(|(user, node)| SecretRef::UserVlessUuid(user.clone(), node.clone())),
        );
        refs.extend(
            self.user_hy2
                .keys()
                .map(|(user, node)| SecretRef::UserHy2Password(user.clone(), node.clone())),
        );
        refs.extend(
            self.user_loop
                .keys()
                .map(|(user, node)| SecretRef::UserLoopUuid(user.clone(), node.clone())),
        );
        refs.extend(
            self.probe_vless
                .keys()
                .cloned()
                .map(SecretRef::ProbeVlessUuid),
        );
        refs.extend(
            self.probe_hy2
                .keys()
                .cloned()
                .map(SecretRef::ProbeHy2Password),
        );
        refs.extend(
            self.probe_loop
                .keys()
                .cloned()
                .map(SecretRef::ProbeLoopUuid),
        );
        refs.sort();
        refs
    }

    /// The number of secrets held.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.alert_topic.is_some())
            + self.reality.len()
            + self.wg_vps.len()
            + self.wg_mac.len()
            + self.hy2_key.len()
            + self.hy2_obfs.len()
            + self.ssh_bootstrap.len()
            + self.dead_man_check.len()
            + self.mac_alive_check.len()
            + self.user_vless.len()
            + self.user_hy2.len()
            + self.user_loop.len()
            + self.probe_vless.len()
            + self.probe_hy2.len()
            + self.probe_loop.len()
    }

    /// Whether the snapshot holds no secrets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every text form of every secret held, for exact-substring scrubbing of
    /// stderr tails (design §12); longest first, so a needle that contains
    /// another is replaced whole.
    #[must_use]
    pub fn needles(&self) -> Vec<Zeroizing<String>> {
        let mut needles: Vec<Zeroizing<String>> = Vec::new();
        let texts = self
            .reality
            .values()
            .map(RealityPrivateKey::expose_text)
            .chain(self.wg_vps.values().map(WgPrivateKey::expose_text))
            .chain(self.wg_mac.values().map(WgPrivateKey::expose_text))
            .chain(self.hy2_obfs.values().map(Password::expose_text))
            .chain(self.ssh_bootstrap.values().map(Ed25519Seed::expose_text))
            .chain(self.alert_topic.iter().map(Password::expose_text))
            .chain(self.user_hy2.values().map(Password::expose_text))
            .chain(self.probe_hy2.values().map(Password::expose_text))
            .chain(
                self.dead_man_check
                    .values()
                    .chain(self.mac_alive_check.values())
                    .chain(self.user_vless.values())
                    .chain(self.user_loop.values())
                    .chain(self.probe_vless.values())
                    .chain(self.probe_loop.values())
                    .map(|uuid| uuid.expose_secret().to_hyphenated()),
            );
        needles.extend(texts);
        needles.extend(self.hy2_key.values().flat_map(Hy2KeyPem::body_lines));
        needles.sort_by(|a, b| {
            b.len()
                .cmp(&a.len())
                .then_with(|| a.as_str().cmp(b.as_str()))
        });
        needles.dedup();
        needles
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn node(text: &str) -> NodeId {
        NodeId::parse(text).unwrap()
    }

    fn user(text: &str) -> UserId {
        UserId::parse(text).unwrap()
    }

    fn uuid(byte: u8) -> SecretMaterial {
        SecretMaterial::Uuid(Secret::new(Uuid::from_random_bytes([byte; 16])))
    }

    fn password(byte: u8) -> SecretMaterial {
        SecretMaterial::Password(Password::from_bytes([byte; 32]).unwrap())
    }

    fn every_ref() -> Vec<SecretRef> {
        let n = node("lon1");
        let u = user("abcdefghij");
        vec![
            SecretRef::NodeRealityPrivate(n.clone()),
            SecretRef::NodeWgVpsPrivate(n.clone()),
            SecretRef::NodeWgMacPrivate(n.clone()),
            SecretRef::NodeHy2Key(n.clone()),
            SecretRef::NodeHy2Obfs(n.clone(), ListenerIdx::new(1)),
            SecretRef::NodeSshBootstrapPrivate(n.clone()),
            SecretRef::UserVlessUuid(u.clone(), n.clone()),
            SecretRef::UserHy2Password(u.clone(), n.clone()),
            SecretRef::UserLoopUuid(u, n.clone()),
            SecretRef::ProbeVlessUuid(n.clone()),
            SecretRef::ProbeHy2Password(n.clone()),
            SecretRef::ProbeLoopUuid(n.clone()),
            SecretRef::AlertTopic,
            SecretRef::NodeDeadManCheck(n.clone()),
            SecretRef::NodeMacAliveCheck(n),
        ]
    }

    fn material_for(kind: SecretKind, byte: u8) -> SecretMaterial {
        match kind {
            SecretKind::RealityPrivateKey => SecretMaterial::RealityPrivateKey(
                RealityPrivateKey::from_bytes([byte; 32]).unwrap(),
            ),
            SecretKind::WgPrivateKey => {
                SecretMaterial::WgPrivateKey(WgPrivateKey::from_bytes([byte; 32]).unwrap())
            }
            SecretKind::Hy2PrivateKey => {
                SecretMaterial::Hy2PrivateKey(Hy2KeyPem::from_der(&[byte; 138]).unwrap())
            }
            SecretKind::Password => password(byte),
            SecretKind::Uuid => uuid(byte),
            SecretKind::Ed25519Seed => {
                SecretMaterial::Ed25519Seed(Ed25519Seed::from_bytes([byte; 32]).unwrap())
            }
        }
    }

    #[test]
    fn debug_never_shows_material() {
        let key = RealityPrivateKey::from_bytes([0x5a; 32]).unwrap();
        let text = key.expose_text();
        let shown = format!("{key:?} {:?}", Secret::new(String::from("hunter2")));
        assert!(!shown.contains(text.as_str()));
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("<redacted>"));
        let material = uuid(9);
        let SecretMaterial::Uuid(inner) = &material else {
            unreachable!()
        };
        let hyphenated = inner.expose_secret().to_hyphenated();
        assert!(!format!("{material:?}").contains(hyphenated.as_str()));
    }

    #[test]
    fn secret_ref_text_round_trips_for_every_variant() {
        for reference in every_ref() {
            let text = reference.to_string();
            assert_eq!(text.parse::<SecretRef>().unwrap(), reference, "{text}");
        }
        assert_eq!(
            SecretRef::NodeHy2Obfs(node("lon1"), ListenerIdx::FIRST).to_string(),
            "node/lon1/hy2-obfs/0"
        );
        // The alert channels' account names and kinds (design §12): the
        // deployment's one topic and each channel node's two checks.
        for (reference, text, kind) in [
            (SecretRef::AlertTopic, "alert/topic", SecretKind::Password),
            (
                SecretRef::NodeDeadManCheck(node("lon1")),
                "node/lon1/dead-man-check",
                SecretKind::Uuid,
            ),
            (
                SecretRef::NodeMacAliveCheck(node("lon1")),
                "node/lon1/mac-alive-check",
                SecretKind::Uuid,
            ),
        ] {
            assert_eq!(reference.to_string(), text);
            assert_eq!(text.parse::<SecretRef>().unwrap(), reference, "{text}");
            assert_eq!(reference.kind(), kind, "{text}");
        }
        for bad in [
            "",
            "node/lon1",
            "node/LON1/hy2-key",
            "node/lon1/hy2-key/extra",
            "node/lon1/hy2-obfs/01",
            "node/lon1/hy2-obfs/256",
            "node/lon1/hy2-obfs/+1",
            "user/abc/lon1/vless-uuid",
            "probe/lon1/reality-private",
            "probe/lon1/alert-topic",
            "node/lon1/alert-topic",
            "node/lon1/alert-topic/0",
            "alert",
            "alert/",
            "alert/topic/",
            "alert/topic/lon1",
            "alert/lon1/topic",
            "Alert/topic",
            "alert/Topic",
            "node/lon1/deadman-check",
            "user/abcdefghij/lon1/mac-alive-check",
        ] {
            assert_eq!(
                bad.parse::<SecretRef>(),
                Err(ModelError::InvalidSecretRef),
                "{bad}"
            );
        }
    }

    /// A snapshot holding every reference of [`every_ref`], the `i`-th with
    /// material of byte `i + 1`, so every secret's text differs.
    fn full_snapshot() -> SecretSnapshot {
        let mut snapshot = SecretSnapshot::new();
        for (reference, material) in every_entry() {
            snapshot
                .insert(SecretEntry::new(reference, material).unwrap())
                .unwrap();
        }
        snapshot
    }

    /// Every reference of [`every_ref`] with distinct material of its kind.
    fn every_entry() -> Vec<(SecretRef, SecretMaterial)> {
        every_ref()
            .into_iter()
            .enumerate()
            .map(|(i, reference)| {
                let byte = u8::try_from(i + 1).unwrap();
                let material = material_for(reference.kind(), byte);
                (reference, material)
            })
            .collect()
    }

    /// The ntfy topic is the deployment's, not a node's: it is the one
    /// reference without a node, and every other names the node it belongs
    /// to in its text.
    #[test]
    fn only_the_alert_topic_belongs_to_no_node() {
        for reference in every_ref() {
            match reference.node() {
                None => assert_eq!(reference, SecretRef::AlertTopic),
                Some(node) => {
                    assert_ne!(reference, SecretRef::AlertTopic);
                    assert_eq!(node.as_str(), "lon1", "{reference}");
                    assert!(reference.to_string().contains("/lon1/"), "{reference}");
                }
            }
        }
        assert!(!SecretRef::AlertTopic.to_string().contains("lon1"));
    }

    #[test]
    fn insert_and_typed_lookup() {
        let snapshot = full_snapshot();
        assert_eq!(snapshot.len(), 15);
        assert_eq!(snapshot.refs(), {
            let mut all = every_ref();
            all.sort();
            all
        });
        let n = node("lon1");
        let u = user("abcdefghij");
        assert_eq!(
            snapshot.reality_private(&n).unwrap().expose_bytes(),
            &[1; 32]
        );
        assert_eq!(
            snapshot.wg_vps_private(&n).unwrap().expose_bytes(),
            &[2; 32]
        );
        assert_eq!(
            snapshot.wg_mac_private(&n).unwrap().expose_bytes(),
            &[3; 32]
        );
        assert!(snapshot.hy2_key(&n).is_ok());
        assert_eq!(
            snapshot
                .hy2_obfs(&n, ListenerIdx::new(1))
                .unwrap()
                .expose_bytes(),
            &[5; 32]
        );
        assert_eq!(snapshot.ssh_bootstrap(&n).unwrap().expose_bytes(), &[6; 32]);
        assert!(snapshot.user_vless_uuid(&u, &n).is_ok());
        assert_eq!(
            snapshot.user_hy2_password(&u, &n).unwrap().expose_bytes(),
            &[8; 32]
        );
        assert!(snapshot.user_loop_uuid(&u, &n).is_ok());
        assert!(snapshot.probe_vless_uuid(&n).is_ok());
        assert_eq!(
            snapshot.probe_hy2_password(&n).unwrap().expose_bytes(),
            &[11; 32]
        );
        assert!(snapshot.probe_loop_uuid(&n).is_ok());
        assert_eq!(snapshot.alert_topic().unwrap().expose_bytes(), &[13; 32]);
        assert_eq!(
            snapshot.dead_man_check(&n).unwrap(),
            &Secret::new(Uuid::from_random_bytes([14; 16]))
        );
        assert_eq!(
            snapshot.mac_alive_check(&n).unwrap(),
            &Secret::new(Uuid::from_random_bytes([15; 16]))
        );
        // Same id, different slot: the VLESS and loopback UUIDs are distinct.
        assert_ne!(
            snapshot.user_vless_uuid(&u, &n).unwrap(),
            snapshot.user_loop_uuid(&u, &n).unwrap()
        );
    }

    #[test]
    fn missing_lookups_name_the_reference() {
        let snapshot = SecretSnapshot::new();
        let n = node("ams1");
        assert_eq!(
            snapshot.hy2_obfs(&n, ListenerIdx::FIRST).unwrap_err(),
            SecretSnapshotError::Missing {
                secret_ref: SecretRef::NodeHy2Obfs(n.clone(), ListenerIdx::FIRST)
            }
        );
        let err = snapshot.probe_loop_uuid(&n).unwrap_err();
        assert_eq!(err.kind(), SecretSnapshotErrorKind::Missing);
        assert_eq!(err.to_string(), "secret probe/ams1/loop-uuid is missing");
        for (err, reference) in [
            (snapshot.alert_topic().unwrap_err(), SecretRef::AlertTopic),
            (
                snapshot.dead_man_check(&n).unwrap_err(),
                SecretRef::NodeDeadManCheck(n.clone()),
            ),
            (
                snapshot.mac_alive_check(&n).unwrap_err(),
                SecretRef::NodeMacAliveCheck(n.clone()),
            ),
        ] {
            assert_eq!(
                err,
                SecretSnapshotError::Missing {
                    secret_ref: reference
                }
            );
        }
        assert!(snapshot.is_empty());
    }

    #[test]
    fn duplicate_inserts_are_rejected_and_the_first_value_is_kept() {
        let mut topics = SecretSnapshot::new();
        let topic = |byte| SecretEntry::new(SecretRef::AlertTopic, password(byte)).unwrap();
        topics.insert(topic(1)).unwrap();
        assert_eq!(
            topics.insert(topic(2)),
            Err(SecretSnapshotError::Duplicate {
                secret_ref: SecretRef::AlertTopic
            })
        );
        assert_eq!(topics.alert_topic().unwrap().expose_bytes(), &[1; 32]);
        assert_eq!(topics.refs(), [SecretRef::AlertTopic]);
        assert_eq!(topics.len(), 1);
        let mut snapshot = SecretSnapshot::new();
        let reference = SecretRef::NodeWgMacPrivate(node("lon1"));
        let entry = |byte| {
            SecretEntry::new(
                reference.clone(),
                material_for(SecretKind::WgPrivateKey, byte),
            )
        };
        snapshot.insert(entry(1).unwrap()).unwrap();
        let err = snapshot.insert(entry(2).unwrap()).unwrap_err();
        assert_eq!(
            err,
            SecretSnapshotError::Duplicate {
                secret_ref: reference
            }
        );
        assert_eq!(err.kind(), SecretSnapshotErrorKind::Duplicate);
        assert_eq!(
            snapshot
                .wg_mac_private(&node("lon1"))
                .unwrap()
                .expose_bytes(),
            &[1; 32]
        );
    }

    #[test]
    fn an_entry_pairs_a_reference_only_with_material_of_its_kind() {
        for reference in every_ref() {
            for &kind in SecretKind::ALL {
                let material = material_for(kind, 3);
                let result = SecretEntry::new(reference.clone(), material.clone());
                if kind == reference.kind() {
                    let entry = result.unwrap();
                    assert_eq!(entry.secret_ref(), reference);
                    assert_eq!(entry.into_parts(), (reference.clone(), material));
                } else {
                    let mismatch = result.unwrap_err();
                    assert_eq!(
                        mismatch,
                        SecretKindMismatch {
                            secret_ref: reference.clone(),
                            expected: reference.kind(),
                            found: kind,
                        }
                    );
                    assert_eq!(
                        mismatch.to_string(),
                        format!(
                            "secret {reference} expects {} material, got {kind}",
                            reference.kind()
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn material_codec_round_trips_every_kind() {
        for &kind in SecretKind::ALL {
            let material = material_for(kind, 0x42);
            let text = material.encode();
            let decoded = SecretMaterial::decode(kind, &text).unwrap();
            assert_eq!(decoded, material, "{kind}");
            assert_eq!(decoded.kind(), kind);
            // Text of one kind is rejected by every other kind's decoder,
            // except where two kinds share an encoding by design.
            for &other in SecretKind::ALL {
                let shares_encoding = matches!(
                    (kind, other),
                    (SecretKind::WgPrivateKey, SecretKind::Ed25519Seed)
                        | (SecretKind::Ed25519Seed, SecretKind::WgPrivateKey)
                        | (SecretKind::RealityPrivateKey, SecretKind::Password)
                        | (SecretKind::Password, SecretKind::RealityPrivateKey)
                );
                if other != kind && !shares_encoding {
                    assert_eq!(
                        SecretMaterial::decode(other, &text),
                        Err(ModelError::InvalidSecret { kind: other }),
                        "{kind} text decoded as {other}"
                    );
                }
            }
        }
    }

    #[test]
    fn all_zero_secret_bytes_are_rejected() {
        assert_eq!(
            RealityPrivateKey::from_bytes([0; 32]),
            Err(ModelError::InvalidSecret {
                kind: SecretKind::RealityPrivateKey
            })
        );
        assert_eq!(
            WgPrivateKey::parse(&format!("{}=", "A".repeat(43))),
            Err(ModelError::InvalidSecret {
                kind: SecretKind::WgPrivateKey
            })
        );
        assert_eq!(
            Password::from_bytes([0; 32]),
            Err(ModelError::InvalidSecret {
                kind: SecretKind::Password
            })
        );
        assert_eq!(
            Ed25519Seed::from_bytes([0; 32]),
            Err(ModelError::InvalidSecret {
                kind: SecretKind::Ed25519Seed
            })
        );
        assert_eq!(
            Hy2KeyPem::from_der(&[]),
            Err(ModelError::InvalidSecret {
                kind: SecretKind::Hy2PrivateKey
            })
        );
        assert_eq!(
            Hy2KeyPem::parse("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
            Err(ModelError::InvalidSecret {
                kind: SecretKind::Hy2PrivateKey
            })
        );
    }

    /// Every text an engine could echo for `material`, computed from the
    /// material itself and not through [`SecretSnapshot::needles`]: the
    /// canonical text, or for a PEM key each base64 body line.
    fn texts_of(material: &SecretMaterial) -> Vec<String> {
        match material {
            SecretMaterial::Hy2PrivateKey(key) => key
                .expose_pem()
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .map(str::to_owned)
                .collect(),
            other => vec![other.encode().as_str().to_owned()],
        }
    }

    #[test]
    fn needles_are_exactly_every_secret_text_longest_first() {
        let snapshot = full_snapshot();
        let needles = snapshot.needles();
        let found: std::collections::BTreeSet<&str> =
            needles.iter().map(|needle| needle.as_str()).collect();
        let mut expected = std::collections::BTreeSet::new();
        for (reference, material) in every_entry() {
            let texts = texts_of(&material);
            assert!(!texts.is_empty(), "{reference}");
            for text in texts {
                assert!(
                    found.contains(text.as_str()),
                    "the needles miss {reference}"
                );
                expected.insert(text);
            }
        }
        let expected: std::collections::BTreeSet<&str> =
            expected.iter().map(String::as_str).collect();
        assert_eq!(found, expected, "the needles hold nothing but secret texts");
        assert_eq!(needles.len(), found.len(), "no needle is repeated");
        assert!(
            needles
                .windows(2)
                .all(|pair| pair[0].len() >= pair[1].len())
        );
    }

    /// Records whether `zeroize` ran, so the test can observe `Drop`.
    #[derive(Clone)]
    struct ZeroizeProbe(std::rc::Rc<std::cell::Cell<u32>>);

    impl Zeroize for ZeroizeProbe {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn dropping_a_secret_zeroizes_its_value_once() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let secret = Secret::new(ZeroizeProbe(calls.clone()));
        let copy = secret.clone();
        assert_eq!(calls.get(), 0);
        drop(secret);
        assert_eq!(calls.get(), 1);
        drop(copy);
        assert_eq!(calls.get(), 2);
    }

    proptest! {
        #[test]
        fn key_texts_round_trip(bytes in proptest::array::uniform32(1_u8..)) {
            let reality = RealityPrivateKey::from_bytes(bytes).unwrap();
            prop_assert_eq!(RealityPrivateKey::parse(&reality.expose_text()).unwrap(), reality);
            let wg = WgPrivateKey::from_bytes(bytes).unwrap();
            prop_assert_eq!(wg.expose_text().len(), 44);
            prop_assert_eq!(WgPrivateKey::parse(&wg.expose_text()).unwrap(), wg);
            let password = Password::from_bytes(bytes).unwrap();
            prop_assert_eq!(password.expose_text().len(), 43);
            prop_assert_eq!(Password::parse(&password.expose_text()).unwrap(), password);
        }

        #[test]
        fn hy2_key_pem_round_trips(der in proptest::collection::vec(any::<u8>(), 1..512)) {
            let key = Hy2KeyPem::from_der(&der).unwrap();
            prop_assert_eq!(Hy2KeyPem::parse(key.expose_pem()).unwrap(), key);
        }
    }
}
