// SPDX-License-Identifier: GPL-3.0-or-later

//! Why a document, a page or the ledger was refused. Every error names
//! entries by their number and orders and users by their ids, never a
//! label, and never echoes text from the portal but through [`printable`].

use super::feed::{FEED_FORMAT, MAX_FEED_BYTES, MAX_FEED_ENTRIES};
use super::ids::OrderId;
use super::ledger::{LEDGER_VERSION, MAX_LEDGER_BYTES};

/// The most characters of a decoder's message kept in an error.
pub const MAX_DETAIL_CHARS: usize = 200;

/// `text` with every character outside printable ASCII escaped, and cut to
/// [`MAX_DETAIL_CHARS`] characters, so that a message quoting the portal's
/// document (a key's name, say) cannot break or forge a log line.
#[must_use]
pub fn printable(text: &str) -> String {
    let mut kept = String::new();
    for character in text.chars() {
        let escaped = if (' '..='~').contains(&character) {
            character.to_string()
        } else {
            character.escape_unicode().to_string()
        };
        if kept.len() + escaped.len() > MAX_DETAIL_CHARS {
            kept.push('…');
            break;
        }
        kept.push_str(&escaped);
    }
    kept
}

/// The portal's document was refused whole: nothing of it is used and the
/// cursor stays (contract §5.5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// Larger than [`MAX_FEED_BYTES`].
    #[error("the document is larger than {MAX_FEED_BYTES} bytes")]
    TooLarge,
    /// Not JSON, or not of the document's shape: a key missing, added,
    /// repeated or of another type.
    #[error("the document does not decode: {detail}")]
    Malformed {
        /// The decoder's message, through [`printable`].
        detail: String,
    },
    /// Its `format` is not [`FEED_FORMAT`].
    #[error("the document is not of the format {FEED_FORMAT}")]
    WrongFormat,
    /// Its `version` is not 1.
    #[error("the document's version is {}, and this build reads version 1", found.map_or_else(|| "not a number".to_owned(), |version| version.to_string()))]
    WrongVersion {
        /// The version written, if it is a whole number.
        found: Option<u64>,
    },
    /// It answers another cursor than the pull asked with.
    #[error("the document answers after={found}, and the pull asked after={asked}")]
    AfterMismatch {
        /// The cursor asked with.
        asked: u64,
        /// The cursor the document names.
        found: u64,
    },
    /// Its time is outside 1970-01-01 to 9999-12-31.
    #[error("the document's time is outside 1970-01-01 to 9999-12-31")]
    GeneratedOutOfRange,
    /// It holds more than [`MAX_FEED_ENTRIES`] entries.
    #[error("the document holds {count} entries, more than {MAX_FEED_ENTRIES}")]
    TooManyEntries {
        /// How many.
        count: usize,
    },
    /// An entry's number is not above the cursor and the entry before it.
    #[error("entry {seq} does not come after {after}")]
    SeqNotAscending {
        /// The entry's number.
        seq: u64,
        /// The cursor or the number before it.
        after: u64,
    },
    /// An entry is not valid.
    #[error("entry {seq}: {fault}")]
    Entry {
        /// The entry's number.
        seq: u64,
        /// What is wrong with it.
        fault: EntryFault,
    },
    /// `next` is not the last entry's number, or the cursor without one.
    #[error("the document's next is {next}, and it ends at {expected}")]
    NextMismatch {
        /// `next`.
        next: u64,
        /// The last entry's number, or `after`.
        expected: u64,
    },
    /// `more` is true and there is no entry, which would ask for the same
    /// page for ever.
    #[error("the document says more entries follow, and holds none")]
    MoreWithoutEntries,
}

/// What is wrong with one entry of the portal's document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntryFault {
    /// `kind` is not `grant`, `refund` or `dispute`.
    #[error("its kind is not grant, refund or dispute")]
    Kind,
    /// The amounts present are not those of its kind: a grant has none, a
    /// refund `amount_refunded` and `refunded_in_full`, a dispute
    /// `amount_disputed`, and every other is `null`.
    #[error("its amounts are not those of its kind")]
    Amounts,
    /// `order` is not an order id.
    #[error("its order is not an order id")]
    Order,
    /// `user` is not a Mooring user id.
    #[error("its user is not a Mooring user id")]
    User,
    /// `plan` is not a plan id.
    #[error("its plan is not a plan id")]
    Plan,
    /// `plan_kind` is not `month`, `month_auto` or `traffic`.
    #[error("its plan kind is not month, month_auto or traffic")]
    PlanKind,
    /// `days` is 0 or more than 4 294 967 295.
    #[error("its days are not between 1 and 4294967295")]
    Days,
    /// `traffic_bytes` is 0.
    #[error("its traffic_bytes is 0")]
    TrafficBytes,
    /// `amount` is 0.
    #[error("its amount is 0")]
    Amount,
    /// `currency` is not three lower-case letters.
    #[error("its currency is not three lower-case letters")]
    Currency,
    /// `paid_at` is outside 1970-01-01 to 9999-12-31.
    #[error("its paid_at is outside 1970-01-01 to 9999-12-31")]
    PaidAt,
    /// `recorded_at` is outside 1970-01-01 to 9999-12-31.
    #[error("its recorded_at is outside 1970-01-01 to 9999-12-31")]
    RecordedAt,
    /// `renewal_of` is neither `null` nor an order id.
    #[error("its renewal_of is not an order id")]
    RenewalOf,
    /// It renews an order and its plan is not `month_auto`.
    #[error("it renews an order, and its plan kind is not month_auto")]
    RenewalOfAnotherKind,
    /// It names its own order as the one it renews.
    #[error("it renews its own order")]
    RenewalOfItself,
}

/// How an entry contradicts what the ledger holds of its order: the portal
/// never changes an order, disputes one twice, or grants one after a refund
/// or dispute of it (contract §1, §4, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Contradiction {
    /// The order's terms differ from those recorded.
    #[error("it gives the order other terms than recorded")]
    TermsDiffer,
    /// The order was recorded from a document of the other Stripe mode.
    #[error("it names the order in the other Stripe mode (test or live) than recorded")]
    ModeDiffers,
    /// A grant for an order known only from a refund or a dispute.
    #[error("it grants the order after a refund or dispute of it")]
    GrantAfterOtherEntries,
    /// A second dispute, of another amount.
    #[error("it disputes the order again, with another amount")]
    SecondDispute,
}

/// Why a page was not applied to the ledger.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyRefusal {
    /// The page's orders were paid in Stripe's test mode and the operator is
    /// not rehearsing: nothing is granted and the cursor stays (contract
    /// §5.3).
    #[error("the portal's payments are of Stripe's test mode, and no rehearsal is on")]
    TestMode,
    /// The page follows another cursor than the ledger's.
    #[error("the page follows entry {after}, and the ledger's cursor is {cursor}")]
    CursorMoved {
        /// The page's cursor.
        after: u64,
        /// The ledger's.
        cursor: u64,
    },
    /// An entry contradicts the ledger: the whole page is refused, and the
    /// pull stops (design §9.6).
    #[error("entry {seq} of order {order}: {contradiction}")]
    Contradicted {
        /// The entry's number.
        seq: u64,
        /// The order.
        order: OrderId,
        /// How.
        contradiction: Contradiction,
    },
}

/// The ledger file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// It does not decode as the ledger's version-1 document.
    #[error("the payment ledger does not decode")]
    Decode(#[source] serde_json::Error),
    /// It is of another version than [`LEDGER_VERSION`].
    #[error(
        "the payment ledger is of version {found}, and this build reads version {LEDGER_VERSION}"
    )]
    UnknownVersion {
        /// The version written.
        found: u32,
    },
    /// It decodes and breaks one of its rules.
    #[error("the payment ledger is inconsistent: {what}")]
    Inconsistent {
        /// The rule broken.
        what: &'static str,
    },
    /// Encoding failed.
    #[error("the payment ledger could not be encoded")]
    Encode(#[source] serde_json::Error),
    /// It is larger than [`MAX_LEDGER_BYTES`].
    #[error("the payment ledger is larger than {MAX_LEDGER_BYTES} bytes")]
    TooLarge,
}
