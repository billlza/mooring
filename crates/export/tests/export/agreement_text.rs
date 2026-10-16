// SPDX-License-Identifier: GPL-3.0-or-later

//! The user agreement's text is bound to its revision (decision F9): users
//! accept a revision, so any change to the text they read must come with a
//! new `AgreementVersion::CURRENT`, which every user then accepts again
//! before their next file. A Level 1 drift check: it detects an accidental
//! edit, not a malicious one.

use mooring_model::AgreementVersion;
use sha2::{Digest as _, Sha256};

const AGREEMENT: &str = include_str!("../../../../docs/runbooks/user-agreement.md");

/// SHA-256 of the user-visible text of revision 1.
const REVISION_1_SHA256: &str = "feccdff92e09d6ed299ea4ac31b0dcd31c104e7025ef2d3cc68c3a19811aaacf";

/// The text the user reads: everything after the operator notes, a comment
/// whose closing `-->` stands on its own line (the licence comment before it
/// closes on its first line). The notes may change without a new revision.
fn user_visible(text: &str) -> &str {
    assert!(
        !text.contains('\r'),
        "the agreement must use LF line endings"
    );
    let (_, visible) = text
        .split_once("\n-->\n")
        .expect("the agreement starts with the operator notes comment");
    assert!(
        visible.starts_with("# "),
        "the user-visible text starts with the title"
    );
    visible
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn the_agreement_text_is_bound_to_its_revision() {
    let expected = match AgreementVersion::CURRENT.get() {
        1 => REVISION_1_SHA256,
        revision => panic!("record the digest of agreement revision {revision} here"),
    };
    assert_eq!(
        sha256_hex(user_visible(AGREEMENT)),
        expected,
        "the user-visible agreement text changed: bump AgreementVersion::CURRENT and record \
         the new digest, or revert the edit"
    );
    // Both the title and the sentence the user says name the revision the
    // build ships.
    let name = format!("《Mooring 使用约定》第 {} 版", AgreementVersion::CURRENT);
    let visible = user_visible(AGREEMENT);
    assert!(visible.starts_with(&format!("# {name}\n")), "{name}");
    assert!(
        visible.contains(&format!("\n> 我已阅读并同意{name}\n")),
        "{name}"
    );
}

/// The licence line and the operator notes are outside the hashed text, and
/// every byte from the title on is inside it.
#[test]
fn only_the_text_from_the_title_on_is_hashed() {
    let document = |notes: &str, body: &str| {
        format!("<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\n<!--\n  {notes}\n-->\n{body}")
    };
    let body = "# 《Mooring 使用约定》第 1 版\n\n正文。\n";
    assert_eq!(user_visible(&document("Operator notes.", body)), body);
    assert_eq!(
        user_visible(&document("Other notes.", body)),
        user_visible(&document("Operator notes.", body))
    );
    assert_ne!(
        sha256_hex(user_visible(&document("Operator notes.", body))),
        sha256_hex(user_visible(&document(
            "Operator notes.",
            "# 《Mooring 使用约定》第 1 版\n\n正文！\n"
        )))
    );
}

/// A checkout with CRLF line endings would change every byte of the digest;
/// it is refused with a message that says so.
#[test]
#[should_panic(expected = "the agreement must use LF line endings")]
fn crlf_line_endings_are_refused_by_name() {
    let _ = user_visible("<!--\r\n  notes\r\n-->\r\n# title\r\n");
}
