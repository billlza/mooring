// SPDX-License-Identifier: GPL-3.0-or-later

//! The random source behind every generator.
//!
//! Production code draws only from [`OsRandom`], the operating system's
//! CSPRNG through `getrandom`. The [`RandomSource`] trait is crate-private so
//! tests can substitute deterministic or failing sources while no caller
//! outside the crate can feed generators predictable bytes.

use zeroize::Zeroizing;

use crate::error::KeysError;

/// A source of cryptographically secure random bytes.
pub(crate) trait RandomSource {
    /// Fills all of `dest` with random bytes.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), getrandom::Error>;
}

/// The operating system's CSPRNG (`getentropy` on macOS, `getrandom` on Linux).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), getrandom::Error> {
        getrandom::fill(dest)
    }
}

/// Draws `N` random bytes into a buffer that is zeroized when dropped.
pub(crate) fn draw<const N: usize>(
    source: &mut impl RandomSource,
) -> Result<Zeroizing<[u8; N]>, KeysError> {
    let mut bytes = Zeroizing::new([0_u8; N]);
    source
        .fill(bytes.as_mut_slice())
        .map_err(KeysError::Entropy)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeysErrorKind;
    use crate::testing::{CountingRandom, FailingRandom};

    #[test]
    fn draw_returns_the_source_bytes() {
        let bytes = draw::<4>(&mut CountingRandom::starting_at(7)).unwrap();
        assert_eq!(*bytes, [7, 8, 9, 10]);
    }

    #[test]
    fn a_failing_source_is_an_entropy_error() {
        let error = draw::<32>(&mut FailingRandom).unwrap_err();
        assert_eq!(error, KeysError::Entropy(getrandom::Error::UNSUPPORTED));
        assert_eq!(error.kind(), KeysErrorKind::Entropy);
    }

    #[test]
    fn the_os_source_fills_every_byte() {
        // Two 32-byte draws collide with probability 2^-256.
        let first = draw::<32>(&mut OsRandom).unwrap();
        let second = draw::<32>(&mut OsRandom).unwrap();
        assert_ne!(*first, *second);
        assert_ne!(*first, [0; 32]);
    }
}
