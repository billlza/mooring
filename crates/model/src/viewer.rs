// SPDX-License-Identifier: GPL-3.0-or-later

//! Remote viewers (design §15.9, decision F5, 2026-10-08): keys allowed to
//! read the node's status read-only over SSH and to close the gate for an
//! operator hold, from the operator's phone.

use serde::{Deserialize, Serialize};

use crate::date::CalendarDate;
use crate::ids::LocalLabel;
use crate::keys::Ed25519Pub;

/// A remote viewer: a key pair generated on the operator's phone, of which
/// only the public half is imported, through
/// [`Ed25519Pub::parse_ssh_authorized_key`]. Viewers are unique by key.
///
/// Adding or removing a viewer is a configuration change: every node's
/// bundle carries the viewer keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Viewer {
    /// The viewer's public key; unique among viewers.
    pub key: Ed25519Pub,
    /// A Mac-only name for the key (for example "phone"); never rendered
    /// into a bundle or sent to a node.
    pub label: LocalLabel,
    /// The day the key was imported.
    pub added_on: CalendarDate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn viewer() -> Viewer {
        Viewer {
            key: Ed25519Pub::from_bytes([0x7e; 32]).unwrap(),
            label: LocalLabel::parse("phone").unwrap(),
            added_on: CalendarDate::parse("2026-10-08").unwrap(),
        }
    }

    /// The record's exact encoding; every key is required and no other is
    /// accepted.
    #[test]
    fn the_viewer_record_has_a_fixed_encoding() {
        let json = r#"{"key":"fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4=","label":"phone","added_on":"2026-10-08"}"#;
        assert_eq!(serde_json::to_string(&viewer()).unwrap(), json);
        assert_eq!(serde_json::from_str::<Viewer>(json).unwrap(), viewer());
        for bad in [
            json.replacen('{', r#"{"zz_unknown":true,"#, 1),
            json.replace(
                r#""key":"fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4=","#,
                "",
            ),
            json.replace(r#""label":"phone","#, ""),
            json.replace(r#","added_on":"2026-10-08""#, ""),
            // An all-zero key, the authorized-keys form, an empty label and
            // an impossible date.
            json.replace(
                "fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4=",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
            json.replace(
                r#""fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4=""#,
                &format!("{:?}", viewer().key.ssh_authorized_key()),
            ),
            json.replace(r#""phone""#, r#""""#),
            json.replace("2026-10-08", "2026-02-30"),
        ] {
            assert_ne!(bad, json);
            assert!(serde_json::from_str::<Viewer>(&bad).is_err(), "{bad}");
        }
    }

    /// A phone's key is imported from its authorized-keys line, and the
    /// record keeps exactly that key.
    #[test]
    fn a_viewer_key_comes_from_an_authorized_keys_line() {
        let line = viewer().key.ssh_authorized_key();
        assert_eq!(
            Ed25519Pub::parse_ssh_authorized_key(&line).unwrap(),
            viewer().key
        );
    }
}
