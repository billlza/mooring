// SPDX-License-Identifier: GPL-3.0-or-later

//! Xray's API output (design §11.5) as the pinned source prints it:
//! `statsquery`'s per-email uplink and downlink counters and `statssys`'s
//! uptime and heap, a value left out read as zero (Xray leaves zeros out)
//! and any other shape of either refused.

use std::collections::BTreeMap;

use super::counters;
use crate::accounting::stats::{QueryFailed, SysStats, parse_query, parse_sys};

#[test]
fn statsquery_is_read_as_the_pinned_source_prints_it() {
    let printed = br#"{
    "stat": [
        {
            "name": "user>>>u01@reality>>>traffic>>>downlink",
            "value": 2048
        },
        {
            "name": "user>>>probe@hy2>>>traffic>>>uplink"
        },
        {
            "name": "user>>>u01@reality>>>traffic>>>uplink",
            "value": 512
        },
        {
            "name": "user>>>probe@hy2>>>traffic>>>downlink",
            "value": 15
        }
    ]
}

"#;
    assert_eq!(
        parse_query(printed),
        Ok(counters(&[
            ("u01@reality", 512, 2048),
            ("probe@hy2", 0, 15)
        ]))
    );
    assert_eq!(
        parse_query(b"{}\n\n"),
        Ok(BTreeMap::new()),
        "nothing matched"
    );
    let pair = |up: &str, down: &str| {
        format!(
            r#"{{"stat":[{{"name":"user>>>u01@reality>>>traffic>>>uplink"{up}}},{{"name":"user>>>u01@reality>>>traffic>>>downlink"{down}}}]}}"#
        )
    };
    assert_eq!(
        parse_query(pair(r#","value":3"#, "").as_bytes()),
        Ok(counters(&[("u01@reality", 3, 0)]))
    );
    for bad in [
        r#"{"stat":[{"name":"user>>>u01@reality>>>traffic>>>uplink","value":1}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>u01@reality>>>traffic>>>uplink"},{"name":"user>>>u01@reality>>>traffic>>>uplink"},{"name":"user>>>u01@reality>>>traffic>>>downlink"}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>u01@reality>>>online"}]}"#.to_owned(),
        r#"{"stat":[{"name":"inbound>>>reality-in>>>traffic>>>uplink"}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>U 1@reality>>>traffic>>>uplink"},{"name":"user>>>U 1@reality>>>traffic>>>downlink"}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>u01@reality>>>traffic>>>sideways"}]}"#.to_owned(),
        pair(r#","value":-1"#, ""),
        pair(r#","value":"1""#, ""),
        pair(r#","extra":1"#, ""),
        r#"{"stats":[]}"#.to_owned(),
        "failed to dial 127.0.0.1:10085".to_owned(),
    ] {
        assert_eq!(parse_query(bad.as_bytes()), Err(QueryFailed), "{bad}");
    }
}

#[test]
fn statssys_is_read_for_its_uptime_and_heap() {
    let printed = b"{\n    \"Alloc\": 52428800,\n    \"Frees\": 9,\n    \"LiveObjects\": 3,\n    \"Mallocs\": 12,\n    \"NumGC\": 4,\n    \"NumGoroutine\": 41,\n    \"PauseTotalNs\": 77,\n    \"Sys\": 90000000,\n    \"TotalAlloc\": 99,\n    \"Uptime\": 3600\n}\n\n";
    assert_eq!(
        parse_sys(printed),
        Ok(SysStats {
            uptime_secs: 3600,
            alloc_bytes: 52_428_800
        })
    );
    assert_eq!(
        parse_sys(br#"{"NumGoroutine": 1}"#),
        Ok(SysStats {
            uptime_secs: 0,
            alloc_bytes: 0
        }),
        "a zero is left out"
    );
    for bad in ["[]", r#"{"Uptime":"1"}"#, r#"{"Alloc":-1}"#, "not json"] {
        assert_eq!(parse_sys(bad.as_bytes()), Err(QueryFailed), "{bad}");
    }
}
