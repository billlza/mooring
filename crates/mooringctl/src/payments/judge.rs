// SPDX-License-Identifier: GPL-3.0-or-later

//! What the portal's answer to a pull comes to (contract §2): a page to
//! apply, a document refused, a stop, or a wait; and what Stripe's answer
//! to a lookup of the check against Stripe comes to (design §9.6). Pure:
//! the pull acts on it.

use std::time::Duration;

use mooring_daemon_core::payments::{FeedError, FeedPage, StopReason, printable};
use serde::Deserialize;

use super::curl::PortalAnswer;

/// How often the pull asks while nothing goes wrong, and how long it waits
/// after a 429 that names no wait it can read.
pub(crate) const PULL_EVERY: Duration = Duration::from_secs(300);

/// The longest `Retry-After` the pull waits.
pub(crate) const RETRY_AFTER_MOST: Duration = Duration::from_secs(86_400);

/// The most characters of a portal's failure text kept in a note.
const MAX_TEXT_CHARS: usize = 200;

/// What one answer comes to.
#[derive(Debug)]
pub(crate) enum Judged {
    /// 200 with a document that decodes: a page to apply.
    Page(FeedPage),
    /// 200 with a document refused whole.
    Refused(FeedError),
    /// 400, 401 or 409: stop until the settings change.
    Stop {
        /// Why.
        reason: StopReason,
        /// The portal's text, escaped.
        text: String,
    },
    /// 404: the portal sells nothing.
    NotSelling,
    /// 429: wait.
    Throttled {
        /// How long, within bounds.
        wait: Duration,
        /// What the portal said, if it said anything.
        stated: Option<String>,
    },
    /// 5xx.
    PortalFailed {
        /// The status.
        status: u16,
        /// The portal's text, escaped.
        text: String,
    },
    /// Any other status, a redirect among them.
    Unexpected {
        /// The status.
        status: u16,
        /// The portal's text, escaped.
        text: String,
    },
}

/// The body's text, escaped and cut, for a note.
fn body_text(body: &[u8]) -> String {
    printable(String::from_utf8_lossy(body).trim())
        .chars()
        .take(MAX_TEXT_CHARS)
        .collect()
}

/// What `answer` to a pull after `asked` comes to.
pub(crate) fn judge(answer: PortalAnswer, asked: u64) -> Judged {
    let text = || body_text(&answer.body);
    match answer.status {
        200 => match FeedPage::decode(&answer.body, asked) {
            Ok(page) => Judged::Page(page),
            Err(error) => Judged::Refused(error),
        },
        400 => Judged::Stop {
            reason: StopReason::BadRequest,
            text: text(),
        },
        401 => Judged::Stop {
            reason: StopReason::Unauthorized,
            text: text(),
        },
        409 => Judged::Stop {
            reason: StopReason::Conflict,
            text: text(),
        },
        404 => Judged::NotSelling,
        429 => Judged::Throttled {
            wait: retry_after(answer.retry_after.as_deref()),
            stated: answer.retry_after,
        },
        status @ 500..=599 => Judged::PortalFailed {
            status,
            text: text(),
        },
        status => Judged::Unexpected {
            status,
            text: text(),
        },
    }
}

/// What Stripe's answer to a lookup comes to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StripeJudged {
    /// 200: the page, for the lookup to read.
    Page(Vec<u8>),
    /// 400, 401, 403 or 404: stop until the settings change; retrying the
    /// same request with the same key cannot help.
    Stop {
        /// Why.
        reason: StopReason,
        /// Stripe's error type and code ([`judge_stripe`]).
        text: String,
    },
    /// 429: wait.
    Throttled {
        /// How long, within bounds.
        wait: Duration,
        /// What Stripe said, if it said anything.
        stated: Option<String>,
    },
    /// Any other status, 5xx among them: try again later.
    Failed {
        /// The status.
        status: u16,
        /// Stripe's error type and code ([`judge_stripe`]).
        text: String,
    },
}

/// Stripe's error document, as far as a note reads it.
#[derive(Deserialize)]
struct StripeErrorBody {
    error: StripeError,
}

/// Stripe's error, as far as a note reads it: its type and code, never
/// its message, which may name the account and part of the key.
#[derive(Deserialize)]
struct StripeError {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

/// What a note keeps of Stripe's error answer `body`: the error's type
/// and code, escaped and cut, and nothing else of it. Of a body that is not
/// Stripe's error document only its length is kept, since a document of
/// another shape may still carry Stripe's message.
fn stripe_error_text(body: &[u8]) -> String {
    match serde_json::from_slice::<StripeErrorBody>(body) {
        Ok(StripeErrorBody { error }) => {
            let said = [error.kind, error.code]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(": ");
            if said.is_empty() {
                "an error without a type or code".to_owned()
            } else {
                body_text(said.as_bytes())
            }
        }
        Err(_) => format!(
            "an answer of {} bytes that is not Stripe's error document",
            body.len()
        ),
    }
}

/// What `answer` to a lookup at Stripe comes to. A note keeps only
/// Stripe's error type and code ([`stripe_error_text`]).
pub(crate) fn judge_stripe(answer: PortalAnswer) -> StripeJudged {
    let text = || stripe_error_text(&answer.body);
    match answer.status {
        200 => StripeJudged::Page(answer.body),
        400 | 404 => StripeJudged::Stop {
            reason: StopReason::StripeBadRequest,
            text: text(),
        },
        401 => StripeJudged::Stop {
            reason: StopReason::StripeUnauthorized,
            text: text(),
        },
        403 => StripeJudged::Stop {
            reason: StopReason::StripeForbidden,
            text: text(),
        },
        429 => StripeJudged::Throttled {
            wait: retry_after(answer.retry_after.as_deref()),
            stated: answer.retry_after,
        },
        status => StripeJudged::Failed {
            status,
            text: text(),
        },
    }
}

/// The wait a `Retry-After` of whole seconds asks for, between 1 s and
/// [`RETRY_AFTER_MOST`]; without one, or one that is not whole seconds (the
/// portal sends seconds), [`PULL_EVERY`].
pub(crate) fn retry_after(stated: Option<&str>) -> Duration {
    let seconds = stated
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<u64>().ok());
    match seconds {
        Some(seconds) => {
            Duration::from_secs(seconds).clamp(Duration::from_secs(1), RETRY_AFTER_MOST)
        }
        None => PULL_EVERY,
    }
}
