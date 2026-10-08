// SPDX-License-Identifier: GPL-3.0-or-later

//! Test-only random sources and decoding helpers, and (on macOS) the runners
//! for the system tools the encoders are cross-checked against.

#[cfg(target_os = "macos")]
pub(crate) mod tools;

use crate::random::RandomSource;

/// A source whose every draw fails, as a broken `getrandom` backend would.
#[derive(Debug)]
pub(crate) struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
}

/// A source that returns only zero bytes, as a broken CSPRNG might.
#[derive(Debug)]
pub(crate) struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), getrandom::Error> {
        dest.fill(0);
        Ok(())
    }
}

/// A deterministic source that returns consecutive byte values.
#[derive(Debug)]
pub(crate) struct CountingRandom(u8);

impl CountingRandom {
    /// The first byte drawn is `first`; later bytes count up, wrapping.
    pub(crate) const fn starting_at(first: u8) -> Self {
        Self(first)
    }
}

impl RandomSource for CountingRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), getrandom::Error> {
        for byte in dest {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// A source that replays fixed bytes, then fails once they run out.
#[derive(Debug)]
pub(crate) struct ReplayRandom(Vec<u8>);

impl ReplayRandom {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl RandomSource for ReplayRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), getrandom::Error> {
        if dest.len() > self.0.len() {
            return Err(getrandom::Error::UNEXPECTED);
        }
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

/// Decodes `2 * N` hexadecimal characters.
pub(crate) fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N, "{text}");
    let mut out = [0_u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap();
    }
    out
}
