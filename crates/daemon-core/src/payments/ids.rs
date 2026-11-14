// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal's ids and codes (`docs/portal-contract.md` §5.3), each
//! checked against its alphabet, so that nothing else reaches the ledger,
//! the daemon's log or the console.

use std::fmt;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

/// What the portal hashes before an invoice's id to give the order id of
/// the renewal that the invoice paid ([`OrderId::for_renewal`]).
const RENEWAL_DOMAIN: &[u8] = b"mooring-portal renewal order v1\0";

/// Crockford's base 32 in lower case: the digits and the letters but `i`,
/// `l`, `o` and `u`.
const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// The characters of an order id.
pub const ORDER_ID_CHARS: usize = 20;

/// The most characters of a plan id.
pub const MAX_PLAN_ID_CHARS: usize = 32;

/// An id or code that is not of its alphabet. The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// Not an order id.
    #[error("not an order id: {ORDER_ID_CHARS} characters of Crockford's lower-case base 32")]
    Order,
    /// Not a plan id.
    #[error("not a plan id: 1 to {MAX_PLAN_ID_CHARS} of a-z, 0-9 and '-', not at either end")]
    Plan,
    /// Not a currency.
    #[error("not a currency: three lower-case letters")]
    Currency,
}

/// An order's id at the portal: 20 characters of Crockford's lower-case
/// base 32. It is also the `client_reference_id` of the order's checkout
/// at Stripe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OrderId(String);

impl OrderId {
    /// Accepts exactly 20 characters of Crockford's lower-case base 32.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.len() == ORDER_ID_CHARS && text.bytes().all(|byte| CROCKFORD.contains(&byte)) {
            Ok(Self(text.to_owned()))
        } else {
            Err(IdError::Order)
        }
    }

    /// The id as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id of the order the portal makes for the renewal of a
    /// subscription that the Stripe invoice `invoice` paid (design §9.6;
    /// the portal's `OrderId::for_renewal`): the first 100 bits of
    /// BLAKE2s-256 of the 31 bytes `mooring-portal renewal order v1`, a
    /// zero byte and the invoice's id, five bits to a symbol, most
    /// significant first. Nobody places a renewal's order, so its id is
    /// the invoice's rather than drawn at random: the same invoice always
    /// gives the same id, and two invoices share one no more often than two
    /// random ids do.
    #[must_use]
    pub fn for_renewal(invoice: &str) -> Self {
        let digest = Blake2s256::new()
            .chain_update(RENEWAL_DOMAIN)
            .chain_update(invoice.as_bytes())
            .finalize();
        let bytes = digest.as_slice();
        let id = (0..ORDER_ID_CHARS)
            .map(|index| {
                // The five bits that begin `bit` bits in: in one byte or
                // across two. The last symbol's lie in bytes 11 and 12, so
                // `bit / 8 + 1` is always within the digest.
                let bit = 5 * index;
                let pair = (u16::from(bytes[bit / 8]) << 8) | u16::from(bytes[bit / 8 + 1]);
                let value = (pair >> (11 - bit % 8)) & 0x1f;
                char::from(CROCKFORD[usize::from(value)])
            })
            .collect();
        Self(id)
    }
}

impl TryFrom<String> for OrderId {
    type Error = IdError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<OrderId> for String {
    fn from(id: OrderId) -> Self {
        id.0
    }
}

impl fmt::Display for OrderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A plan's id, as the operator named it in the portal's catalogue: 1 to
/// 32 of `a-z`, `0-9` and `-`, not starting or ending with `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PlanId(String);

impl PlanId {
    /// Accepts 1 to 32 of `a-z`, `0-9` and `-`, not at either end.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let valid = (1..=MAX_PLAN_ID_CHARS).contains(&text.len())
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !text.starts_with('-')
            && !text.ends_with('-');
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(IdError::Plan)
        }
    }
}

impl TryFrom<String> for PlanId {
    type Error = IdError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<PlanId> for String {
    fn from(id: PlanId) -> Self {
        id.0
    }
}

impl fmt::Display for PlanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A currency, as Stripe writes it: three lower-case letters (`gbp`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Currency(String);

impl Currency {
    /// Accepts exactly three of `a-z`.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.len() == 3 && text.bytes().all(|byte| byte.is_ascii_lowercase()) {
            Ok(Self(text.to_owned()))
        } else {
            Err(IdError::Currency)
        }
    }

    /// The code as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Currency {
    type Error = IdError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<Currency> for String {
    fn from(code: Currency) -> Self {
        code.0
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
