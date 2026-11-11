// SPDX-License-Identifier: GPL-3.0-or-later

//! What the portal's answer to a pull comes to (contract §2): a page to
//! apply, a document refused, a stop, or a wait. Pure: the pull acts on
//! it.

use std::time::Duration;

use mooring_daemon_core::payments::{FeedError, FeedPage, StopReason, printable};

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

/// What `answer` to a pull after `asked` comes to.
pub(crate) fn judge(answer: PortalAnswer, asked: u64) -> Judged {
    let text = || {
        printable(String::from_utf8_lossy(&answer.body).trim())
            .chars()
            .take(MAX_TEXT_CHARS)
            .collect::<String>()
    };
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
