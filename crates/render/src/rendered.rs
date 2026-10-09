// SPDX-License-Identifier: GPL-3.0-or-later

//! [`RenderedFile`]: one rendered config's bytes and their SHA-256.

use std::fmt;

use mooring_agent_proto::Sha256Hex;
use mooring_model::Sha256Digest;
use zeroize::Zeroizing;

/// One rendered configuration file. Most files hold secrets, so the bytes
/// are zeroized on drop and `Debug` shows only the length and digest.
///
/// The SHA-256 of the bytes is the file's config digest: an engine is
/// restarted only when the digest of its own config changes (design §7).
#[derive(Clone, PartialEq, Eq)]
pub struct RenderedFile {
    bytes: Zeroizing<Vec<u8>>,
    sha256: Sha256Digest,
}

impl RenderedFile {
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        let sha256 = Sha256Digest::of(&bytes);
        Self { bytes, sha256 }
    }

    /// The file contents: UTF-8 text ending with one newline, or nothing
    /// (`viewer_authorized_keys` with no viewer recorded).
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The SHA-256 of the contents, as the model records digests.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.sha256
    }

    /// The SHA-256 of the contents, as the agent protocol names blobs.
    #[must_use]
    pub const fn sha256(&self) -> Sha256Hex {
        Sha256Hex::from_bytes(*self.sha256.as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn expose_text(&self) -> &str {
        std::str::from_utf8(&self.bytes).unwrap()
    }
}

impl fmt::Debug for RenderedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderedFile")
            .field("len", &self.bytes.len())
            .field("sha256", &self.sha256())
            .finish_non_exhaustive()
    }
}
