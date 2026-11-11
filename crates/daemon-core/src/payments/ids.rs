// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal's ids and codes (`docs/portal-contract.md` §5.3), each
//! checked against its alphabet, so that nothing else reaches the ledger,
//! the daemon's log or the console.

use std::fmt;

use serde::{Deserialize, Serialize};

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
