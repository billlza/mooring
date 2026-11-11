// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's copy of the nodes' abuse records (design §11.8): merged by
//! node and number, a contradiction refused, kept 13 months, read only as
//! a whole valid document.

use mooring_agent_proto::{
    AbuseAction, AbuseCuts, AbuseGuardVersion, AbuseRecord, AbuseRecordsV1, AbuseSeq, OpaqueUserId,
    UnixTime,
};
use mooring_model::NodeId;

use crate::abuse::{
    AbuseRecordsError, AbuseRecordsErrorKind, MAC_ABUSE_RECORDS_PER_NODE, MAC_ABUSE_RETENTION_SECS,
    MacAbuseRecords,
};

const NOW: u64 = 1_791_800_000;

fn node(id: &str) -> NodeId {
    NodeId::parse(id).unwrap()
}

fn record(seq: u64, at: u64, action: AbuseAction) -> AbuseRecord {
    AbuseRecord {
        seq: AbuseSeq::new(seq),
        at: UnixTime::from_secs(at),
        user: OpaqueUserId::new("fxuseraaab").unwrap(),
        guard: AbuseGuardVersion::V1,
        action,
        figures: None,
    }
}

fn page(records: Vec<AbuseRecord>) -> AbuseRecordsV1 {
    let end = records.last().map_or(0, |last| last.seq.get() + 1);
    AbuseRecordsV1::new(AbuseCuts::EMPTY, records, AbuseSeq::new(end)).unwrap()
}

#[test]
fn pages_merge_by_node_and_number_once() {
    let mut copy = MacAbuseRecords::decode(None).unwrap();
    let lon1 = node("lon1");
    let ams1 = node("ams1");
    let first = page(vec![
        record(0, NOW, AbuseAction::OperatorCut),
        record(1, NOW + 5, AbuseAction::Cleared),
    ]);
    assert_eq!(copy.merge(&lon1, &first), Ok(2));
    assert_eq!(copy.merge(&lon1, &first), Ok(0));
    assert_eq!(copy.merge(&ams1, &first), Ok(2), "numbers are per node");
    let later = page(vec![
        record(1, NOW + 5, AbuseAction::Cleared),
        record(2, NOW + 9, AbuseAction::OperatorCut),
    ]);
    assert_eq!(copy.merge(&lon1, &later), Ok(1));
    let seqs: Vec<u64> = copy.records(&lon1).iter().map(|r| r.seq.get()).collect();
    assert_eq!(seqs, [0, 1, 2]);
    assert_eq!(
        copy.nodes().cloned().collect::<Vec<_>>(),
        [ams1, lon1.clone()]
    );
    let bytes = copy.encode().unwrap();
    assert!(bytes.ends_with(b"}\n"));
    assert_eq!(MacAbuseRecords::decode(Some(&bytes)).unwrap(), copy);
}

/// A number the copy holds with other content is refused, and nothing of
/// the page is added.
#[test]
fn a_record_contradicting_the_copy_is_refused_whole() {
    let mut copy = MacAbuseRecords::default();
    let lon1 = node("lon1");
    copy.merge(&lon1, &page(vec![record(0, NOW, AbuseAction::OperatorCut)]))
        .unwrap();
    let before = copy.clone();
    let contradicting = page(vec![
        record(0, NOW, AbuseAction::Cleared),
        record(1, NOW + 1, AbuseAction::Cleared),
    ]);
    let error = copy.merge(&lon1, &contradicting).unwrap_err();
    assert_eq!(
        error,
        AbuseRecordsError::Conflict {
            node: lon1.clone(),
            seq: 0
        }
    );
    assert_eq!(error.kind(), AbuseRecordsErrorKind::Conflict);
    assert_eq!(
        error.to_string(),
        "node lon1 reports abuse record 0 unlike the copy the Mac holds"
    );
    assert_eq!(copy, before);
}

#[test]
fn records_are_kept_thirteen_months() {
    let mut copy = MacAbuseRecords::default();
    let lon1 = node("lon1");
    let ams1 = node("ams1");
    copy.merge(
        &lon1,
        &page(vec![
            record(0, NOW, AbuseAction::OperatorCut),
            record(1, NOW + 10, AbuseAction::Cleared),
        ]),
    )
    .unwrap();
    copy.merge(&ams1, &page(vec![record(0, NOW, AbuseAction::OperatorCut)]))
        .unwrap();
    assert_eq!(
        copy.prune(UnixTime::from_secs(NOW + MAC_ABUSE_RETENTION_SECS)),
        0
    );
    assert_eq!(
        copy.prune(UnixTime::from_secs(NOW + MAC_ABUSE_RETENTION_SECS + 1)),
        2
    );
    assert_eq!(copy.records(&lon1).len(), 1);
    assert!(copy.records(&ams1).is_empty());
    assert_eq!(copy.nodes().count(), 1, "a node left with none goes");
    // A record from after now (a clock that stepped back) stays.
    assert_eq!(copy.prune(UnixTime::from_secs(NOW)), 0);
}

#[test]
fn only_a_whole_valid_document_is_read() {
    for (bytes, kind) in [
        (&b"garbled"[..], AbuseRecordsErrorKind::Undecodable),
        (br#"{"version":1}"#, AbuseRecordsErrorKind::Undecodable),
        (
            br#"{"version":1,"nodes":{},"x":1}"#,
            AbuseRecordsErrorKind::Undecodable,
        ),
        (
            br#"{"version":2,"nodes":{}}"#,
            AbuseRecordsErrorKind::UnsupportedVersion,
        ),
        (
            br#"{"version":1,"nodes":{"Lon1":[]}}"#,
            AbuseRecordsErrorKind::Undecodable,
        ),
    ] {
        assert_eq!(
            MacAbuseRecords::decode(Some(bytes)).unwrap_err().kind(),
            kind,
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }
    // Out of order, and a number repeated: a node never gives either.
    for (first, second) in [(1, 0), (0, 0)] {
        let document = format!(
            r#"{{"version":1,"nodes":{{"lon1":[{},{}]}}}}"#,
            serde_json::to_string(&record(first, NOW, AbuseAction::Cleared)).unwrap(),
            serde_json::to_string(&record(second, NOW, AbuseAction::Cleared)).unwrap()
        );
        let error = MacAbuseRecords::decode(Some(document.as_bytes())).unwrap_err();
        assert_eq!(
            error,
            AbuseRecordsError::OutOfOrder { node: node("lon1") },
            "{first}, {second}"
        );
        assert_eq!(error.kind(), AbuseRecordsErrorKind::OutOfOrder);
        assert_eq!(
            error.to_string(),
            "the abuse records of node lon1 are out of number order or repeat a number"
        );
    }
    assert_eq!(
        AbuseRecordsError::UnsupportedVersion { found: 2 }.to_string(),
        "the abuse records name version 2; this build reads version 1"
    );
    assert_eq!(
        AbuseRecordsError::Unencodable.kind(),
        AbuseRecordsErrorKind::Unencodable
    );
    assert_eq!(
        AbuseRecordsError::Undecodable.kind(),
        AbuseRecordsErrorKind::Undecodable
    );
}

/// A node's records past the bound the Mac keeps are refused rather than
/// any dropped within their retention, whether a merge would pass it or the
/// document read already does.
#[test]
fn a_node_past_the_bound_is_refused() {
    let lon1 = node("lon1");
    let mut copy = MacAbuseRecords::default();
    let mut seq = 0;
    while seq < MAC_ABUSE_RECORDS_PER_NODE as u64 {
        let records = (seq..seq + 512)
            .map(|seq| record(seq, NOW, AbuseAction::Cleared))
            .collect();
        copy.merge(&lon1, &page(records)).unwrap();
        seq += 512;
    }
    let error = copy
        .merge(&lon1, &page(vec![record(seq, NOW, AbuseAction::Cleared)]))
        .unwrap_err();
    assert_eq!(error, AbuseRecordsError::TooMany { node: lon1.clone() });
    assert_eq!(error.kind(), AbuseRecordsErrorKind::TooMany);
    assert_eq!(
        error.to_string(),
        "the Mac keeps at most 65536 abuse records of node lon1"
    );
    assert_eq!(copy.records(&lon1).len(), MAC_ABUSE_RECORDS_PER_NODE);

    // The bound itself is read back; one record past it is refused.
    let at_bound = copy.encode().unwrap();
    assert_eq!(MacAbuseRecords::decode(Some(&at_bound)).unwrap(), copy);
    let mut document: serde_json::Value = serde_json::from_slice(&at_bound).unwrap();
    let records = document["nodes"]["lon1"].as_array_mut().unwrap();
    records.push(serde_json::to_value(record(seq, NOW, AbuseAction::Cleared)).unwrap());
    let past_bound = serde_json::to_vec(&document).unwrap();
    assert_eq!(
        MacAbuseRecords::decode(Some(&past_bound)).unwrap_err(),
        AbuseRecordsError::TooMany { node: lon1 }
    );
}
