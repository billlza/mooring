// SPDX-License-Identifier: GPL-3.0-or-later

//! Which `xray.json` changes the running Xray takes through its API, and
//! how `inbounduser`'s output is read (`txn::xray_users`), on the rendered
//! golden configuration.

use serde_json::{Value, json};

use super::{client, clients, with_clients};
use crate::tests::txn::world::{XRAY, golden};
use crate::txn::xray_users::{Client, classify, parse_held};

/// The golden `xray.json`, as a document.
fn rendered() -> Value {
    serde_json::from_str(&golden(XRAY)).unwrap()
}

/// The golden `xray.json` with user `n`'s two clients for each `n` in
/// `users`.
fn rendered_with(users: &[u8]) -> Value {
    serde_json::from_str(&with_clients(&golden(XRAY), users)).unwrap()
}

/// The inbound tagged `tag` in `config`.
fn inbound<'a>(config: &'a mut Value, tag: &str) -> &'a mut Value {
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|inbound| inbound["tag"] == tag)
        .unwrap()
}

#[test]
fn clients_added_to_the_live_inbounds_are_an_opening() {
    let opening = classify(&rendered(), &rendered_with(&[1, 2])).unwrap();
    assert_eq!(
        opening.added(),
        [
            (
                "reality-in",
                vec!["fxuserzzz1@reality", "fxuserzzz2@reality"]
            ),
            ("hy2-loop-in", vec!["fxuserzzz1@hy2", "fxuserzzz2@hy2"]),
        ]
    );
    // Wherever the renderer puts them: it lists users in id order, so a
    // spare whose id sorts first comes before the users it had.
    let mut next = rendered();
    for (tag, inbound) in [("reality-in", "reality"), ("hy2-loop-in", "hy2")] {
        clients(&mut next, tag).insert(0, client(3, inbound));
    }
    let opening = classify(&rendered(), &next).unwrap();
    assert_eq!(
        opening.added(),
        [
            ("reality-in", vec!["fxuserzzz3@reality"]),
            ("hy2-loop-in", vec!["fxuserzzz3@hy2"]),
        ]
    );
    // An inbound may gain none.
    let mut next = rendered();
    clients(&mut next, "hy2-loop-in").push(client(1, "hy2"));
    let opening = classify(&rendered(), &next).unwrap();
    assert_eq!(
        opening.added(),
        [
            ("reality-in", vec![]),
            ("hy2-loop-in", vec!["fxuserzzz1@hy2"]),
        ]
    );
}

/// `before` and `next` made by `edit` from the golden configuration with
/// user 1's clients added: not an opening.
fn assert_restarts(edit: impl Fn(&mut Value, &mut Value), why: &str) {
    let mut before = rendered();
    let mut next = rendered_with(&[1]);
    assert!(
        classify(&before, &next).is_some(),
        "{why}: the unedited pair"
    );
    edit(&mut before, &mut next);
    assert_eq!(classify(&before, &next), None, "{why}");
}

#[test]
fn nothing_added_is_no_opening() {
    assert_eq!(classify(&rendered(), &rendered()), None);
    assert_restarts(|before, next| *before = next.clone(), "the same clients");
    assert_restarts(
        |before, next| {
            *before = next.clone();
            clients(next, "reality-in").reverse();
            clients(next, "hy2-loop-in").reverse();
        },
        "the same clients in another order",
    );
}

#[test]
fn a_client_removed_or_changed_is_no_opening() {
    assert_restarts(
        |_, next| {
            clients(next, "reality-in").remove(0);
        },
        "a client removed",
    );
    for (field, value) in [
        ("id", json!("6ba7b819-9dad-41d1-80b4-00c04fd430c8")),
        ("flow", json!("")),
        ("level", json!(1)),
        ("email", json!("fxuseraaaz@reality")),
    ] {
        assert_restarts(
            |_, next| clients(next, "reality-in")[0][field] = value.clone(),
            field,
        );
    }
}

#[test]
fn any_other_change_is_no_opening() {
    assert_restarts(
        |_, next| next["policy"]["levels"]["0"]["connIdle"] = json!(301),
        "a policy",
    );
    assert_restarts(
        |_, next| inbound(next, "camo-80")["port"] = json!(8080),
        "another inbound",
    );
    assert_restarts(
        |_, next| {
            inbound(next, "reality-in")["streamSettings"]["realitySettings"]["shortIds"]
                .as_array_mut()
                .unwrap()
                .push(json!("5f1e0000000000aa"));
        },
        "a short id added",
    );
    assert_restarts(
        |_, next| inbound(next, "reality-in")["listen"] = json!("45.67.89.11"),
        "a live inbound's address",
    );
    assert_restarts(
        |_, next| next["api"]["services"] = json!(["HandlerService"]),
        "the API",
    );
}

#[test]
fn a_running_xray_without_the_handler_service_takes_no_opening() {
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                config["api"]["services"] = json!(["StatsService"]);
            }
        },
        "no HandlerService",
    );
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                config["api"]["listen"] = json!("127.0.0.1:10086");
            }
        },
        "another API listener",
    );
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                config.as_object_mut().unwrap().remove("api");
            }
        },
        "no API",
    );
}

/// The live inbounds must have the shape whose users the engine reads back
/// as the file lists them.
#[test]
fn a_live_inbound_of_another_shape_is_no_opening() {
    for (key, value) in [
        ("flow", json!("xtls-rprx-vision")),
        ("testseed", json!([900, 500, 900, 256])),
    ] {
        assert_restarts(
            |before, next| {
                for config in [before, next] {
                    inbound(config, "reality-in")["settings"][key] = value.clone();
                }
            },
            key,
        );
    }
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                inbound(config, "hy2-loop-in")["protocol"] = json!("trojan");
            }
        },
        "another protocol",
    );
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                inbound(config, "hy2-loop-in")["settings"]["decryption"] =
                    json!("mlkem768x25519plus");
            }
        },
        "another decryption",
    );
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                let copy = inbound(config, "hy2-loop-in").clone();
                config["inbounds"].as_array_mut().unwrap().push(copy);
            }
        },
        "an inbound tagged twice",
    );
    assert_restarts(
        |before, next| {
            for config in [before, next] {
                config["inbounds"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|inbound| inbound["tag"] != "hy2-loop-in");
            }
        },
        "no loopback inbound",
    );
}

/// A change made to a client.
type ClientEdit = fn(&mut Value);

/// Each client must list exactly the rendered fields, with a canonical id
/// and an email of its own in any case.
#[test]
fn a_client_of_another_form_is_no_opening() {
    let last = |next: &mut Value| -> Value {
        let added = clients(next, "reality-in").last_mut().unwrap();
        added.take()
    };
    let cases: [(&str, ClientEdit); 5] = [
        ("an unknown field", |added| {
            added["testseed"] = json!([900, 500, 900, 256])
        }),
        ("no level", |added| {
            added.as_object_mut().unwrap().remove("level");
        }),
        ("an id in capitals", |added| {
            added["id"] = json!("6BA7B811-9DAD-41D1-80B4-00C04FD430C8");
        }),
        ("an id without hyphens", |added| {
            added["id"] = json!("6ba7b8119dad41d180b400c04fd430c8");
        }),
        ("an email held in another case", |added| {
            added["email"] = json!("FXUSERAAAB@reality");
        }),
    ];
    for (why, change) in cases {
        assert_restarts(
            |_, next| {
                let mut added = last(next);
                change(&mut added);
                *clients(next, "reality-in").last_mut().unwrap() = added;
            },
            why,
        );
    }
}

/// What `inbounduser` prints, as the pinned source's marshaller writes it:
/// four-space indentation, keys in order, zero and empty fields left out.
#[test]
fn the_users_read_back_are_parsed_as_the_pinned_xray_prints_them() {
    let printed = br#"{
    "users": [
        {
            "account": {
                "_TypedMessage_": "xray.proxy.vless.Account",
                "flow": "xtls-rprx-vision",
                "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"
            },
            "email": "fxuserzzz1@reality"
        },
        {
            "account": {
                "_TypedMessage_": "xray.proxy.vless.Account",
                "id": "7ca7b811-9dad-41d1-80b4-00c04fd430c8"
            },
            "email": "fxuserzzz1@hy2",
            "level": 2
        }
    ]
}

"#;
    assert_eq!(
        parse_held(printed),
        Some(vec![
            Client {
                id: "6ba7b811-9dad-41d1-80b4-00c04fd430c8".to_owned(),
                flow: "xtls-rprx-vision".to_owned(),
                level: 0,
                email: "fxuserzzz1@reality".to_owned(),
            },
            Client {
                id: "7ca7b811-9dad-41d1-80b4-00c04fd430c8".to_owned(),
                flow: String::new(),
                level: 2,
                email: "fxuserzzz1@hy2".to_owned(),
            },
        ])
    );
    assert_eq!(parse_held(b"{}\n\n"), Some(vec![]));
}

/// The engine keys no user without an email, so it may hold two: both are
/// read, and left for the comparison to name.
#[test]
fn users_without_an_email_are_read_as_they_are() {
    let printed = concat!(
        r#"{"users": [{"account": {"_TypedMessage_": "xray.proxy.vless.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"}}, "#,
        r#"{"account": {"_TypedMessage_": "xray.proxy.vless.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c9"}}]}"#
    );
    let client = |id: &str| Client {
        id: id.to_owned(),
        flow: String::new(),
        level: 0,
        email: String::new(),
    };
    assert_eq!(
        parse_held(printed.as_bytes()),
        Some(vec![
            client("6ba7b811-9dad-41d1-80b4-00c04fd430c8"),
            client("6ba7b811-9dad-41d1-80b4-00c04fd430c9"),
        ])
    );
}

#[test]
fn a_reply_the_pinned_xray_never_prints_is_unreadable() {
    let user = |account: &str| {
        format!(r#"{{"users": [{{"email": "fxuserzzz1@reality", "account": {account}}}]}}"#)
    };
    for printed in [
        user(
            r#"{"_TypedMessage_": "xray.proxy.vmess.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"}"#,
        ),
        user(r#"{"id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"}"#),
        user(
            r#"{"_TypedMessage_": "xray.proxy.vless.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8", "testseed": [900, 500, 900, 256]}"#,
        ),
        r#"{"users": [{"email": "fxuserzzz1@reality"}]}"#.to_owned(),
        r#"{"users": [], "count": 0}"#.to_owned(),
        // Two users under one email, which the engine keys folded to lower
        // case: the same user twice, and another id in another case.
        format!(
            r#"{{"users": [{user}, {user}]}}"#,
            user = r#"{"email": "fxuserzzz1@reality", "account": {"_TypedMessage_": "xray.proxy.vless.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"}}"#
        ),
        concat!(
            r#"{"users": [{"email": "fxuserzzz1@reality", "account": {"_TypedMessage_": "xray.proxy.vless.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"}}, "#,
            r#"{"email": "FXUSERZZZ1@reality", "account": {"_TypedMessage_": "xray.proxy.vless.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c9"}}]}"#
        )
        .to_owned(),
        "failed to get inbound user".to_owned(),
        String::new(),
    ] {
        assert_eq!(parse_held(printed.as_bytes()), None, "{printed}");
    }
}
