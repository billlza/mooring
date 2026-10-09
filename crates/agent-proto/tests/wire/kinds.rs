// SPDX-License-Identifier: GPL-3.0-or-later

//! Every `Kind` of every public error enum is asserted here (design §14:
//! `xtask kinds-coverage` requires it). Where the public API can produce an
//! error, the sample is produced through it, which also proves the error is
//! reachable.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor, Read, Write};

use mooring_agent_proto::{
    AgentError, AgentErrorKind, BlobLen, BundleFiles, CertName, EventSeq, EventsV1, HttpStatus,
    IfName, InboundSet, KernelIdent, KernelRelease, LineRequest, MAX_BLOB_BYTES,
    MAX_REQUEST_LINE_BYTES, MacReportV1, NodeName, NoticeBody, NoticeTitle, OpaqueUserId,
    PortRange, ReadError, ReadErrorKind, RedirectUrl, ReportBandNumber, ReportUsage, ReportUserId,
    RequestKind, Resolution, Response, ResponseKind, Role, SeriesRange, SeriesSpan, Sha256Hex,
    SshEd25519Key, StatsEmail, StderrTail, TargetHost, UnitName, UnixTime, UsageBin, UsageMonth,
    UsageSeriesV1, ValueError, ValueErrorKind, WatchConditions, WatchError, WatchErrorKind,
    WriteError, WriteErrorKind, read_blob, read_reply, read_request, write_put_blob, write_request,
};

use crate::fixtures;

fn assert_kinds<K: Copy + Ord + std::fmt::Debug>(all: &[K], sample_kind: impl Fn(K) -> K) {
    let unique: BTreeSet<K> = all.iter().copied().collect();
    assert_eq!(unique.len(), all.len(), "ALL repeats a kind");
    for kind in all {
        assert_eq!(sample_kind(*kind), *kind);
    }
}

fn value_error(kind: ValueErrorKind) -> ValueError {
    match kind {
        ValueErrorKind::Sha256Hex => "ABC".parse::<Sha256Hex>().unwrap_err(),
        ValueErrorKind::BlobTooLarge => BlobLen::new(MAX_BLOB_BYTES + 1).unwrap_err(),
        ValueErrorKind::IfName => IfName::new("a/b").unwrap_err(),
        ValueErrorKind::KernelRelease => KernelRelease::new("").unwrap_err(),
        ValueErrorKind::KernelIdent => KernelIdent::new("BBR").unwrap_err(),
        ValueErrorKind::PortRange => PortRange::new(0, 1).unwrap_err(),
        ValueErrorKind::TargetHost => TargetHost::new("a..b").unwrap_err(),
        ValueErrorKind::UnitName => UnitName::new("-x").unwrap_err(),
        ValueErrorKind::CertName => CertName::new(" ").unwrap_err(),
        ValueErrorKind::RedirectUrl => RedirectUrl::new("").unwrap_err(),
        ValueErrorKind::SshEd25519Key => SshEd25519Key::new("ssh-rsa AAAA").unwrap_err(),
        // Only decoding checks a received tail; it reports this error as the
        // decode error's message (see `a_received_tail_is_checked_when_decoded`).
        ValueErrorKind::StderrTail => ValueError::StderrTail,
        ValueErrorKind::UsageMonth => "2026-13".parse::<UsageMonth>().unwrap_err(),
        ValueErrorKind::OpaqueUserId => OpaqueUserId::new("probe").unwrap_err(),
        ValueErrorKind::StatsEmail => "u01@vless".parse::<StatsEmail>().unwrap_err(),
        ValueErrorKind::HttpStatus => HttpStatus::new(0).unwrap_err(),
        ValueErrorKind::Role => "root".parse::<Role>().unwrap_err(),
        ValueErrorKind::MissingManagedFile => BundleFiles::try_from(&BTreeMap::new()).unwrap_err(),
        ValueErrorKind::DuplicateWatchCondition => {
            WatchConditions::new([WatchError::NftFailed, WatchError::NftFailed]).unwrap_err()
        }
        ValueErrorKind::SeriesSpan => {
            SeriesSpan::new(time(600), time(600), Resolution::FiveMin).unwrap_err()
        }
        ValueErrorKind::RangeTooLarge => {
            SeriesRange::new(time(0), time(36 * 86_400), Resolution::Day).unwrap_err()
        }
        ValueErrorKind::UsageBin => UsageBin::new(time(0), BTreeMap::new()).unwrap_err(),
        ValueErrorKind::UsageSeries => {
            let late = fixtures::usage_series().bins()[0].clone();
            UsageSeriesV1::new(fixtures::usage_series().range(), vec![late.clone(), late])
                .unwrap_err()
        }
        ValueErrorKind::Events => {
            let page = fixtures::events();
            EventsV1::new(page.events().to_vec(), EventSeq::FIRST).unwrap_err()
        }
        ValueErrorKind::InboundSet => InboundSet::try_from(Vec::new()).unwrap_err(),
        ValueErrorKind::NodeName => NodeName::new("Lon1").unwrap_err(),
        ValueErrorKind::ReportUserId => ReportUserId::new("356938035643809").unwrap_err(),
        ValueErrorKind::ReportBandNumber => ReportBandNumber::new(1007).unwrap_err(),
        ValueErrorKind::MacReport => {
            let mut parts = fixtures::mac_report_parts();
            parts.usage = ReportUsage::Unavailable;
            MacReportV1::new(parts).unwrap_err()
        }
        ValueErrorKind::NoticeTitle => NoticeTitle::new("203.0.113.7").unwrap_err(),
        ValueErrorKind::NoticeBody => NoticeBody::new("a\n\nb").unwrap_err(),
    }
}

fn time(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

struct FailingIo;

impl Read for FailingIo {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(5))
    }
}

impl Write for FailingIo {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(28))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_error(kind: ReadErrorKind) -> ReadError {
    let mut empty: &[u8] = b"";
    match kind {
        ReadErrorKind::Io => read_request(&mut io::BufReader::new(FailingIo)).unwrap_err(),
        ReadErrorKind::Sink => {
            read_blob(&mut &b"x"[..], BlobLen::new(1).unwrap(), &mut FailingIo).unwrap_err()
        }
        ReadErrorKind::Empty => read_request(&mut empty).unwrap_err(),
        ReadErrorKind::Unterminated => read_request(&mut &b"\"Hello\""[..]).unwrap_err(),
        ReadErrorKind::TooLarge => {
            read_request(&mut Cursor::new(vec![b' '; MAX_REQUEST_LINE_BYTES + 1])).unwrap_err()
        }
        ReadErrorKind::Malformed => read_request(&mut &b"{}\n"[..]).unwrap_err(),
        ReadErrorKind::BlobTruncated => {
            read_blob(&mut empty, BlobLen::new(1).unwrap(), &mut Vec::new()).unwrap_err()
        }
        ReadErrorKind::TrailingBytes => {
            read_reply(&mut &b"{\"Ok\":\"BootstrapRevoked\"}\nx"[..]).unwrap_err()
        }
    }
}

fn write_error(kind: WriteErrorKind) -> WriteError {
    match kind {
        WriteErrorKind::Io => write_request(&mut FailingIo, &LineRequest::Hello).unwrap_err(),
        // No wire type can fail to encode (every map key is a string), so
        // this sample wraps a decoder error to exercise the mapping only.
        WriteErrorKind::Encode => WriteError::Encode(serde_json::from_str::<u8>("x").unwrap_err()),
        WriteErrorKind::TooLarge => {
            let blobs = (0_u32..16_000)
                .map(|index| {
                    let mut bytes = [0_u8; 32];
                    bytes[..4].copy_from_slice(&index.to_be_bytes());
                    Sha256Hex::from_bytes(bytes)
                })
                .collect();
            write_request(&mut Vec::new(), &LineRequest::HaveBlobs { blobs }).unwrap_err()
        }
        WriteErrorKind::BlobTooLarge => {
            let oversized = vec![0_u8; usize::try_from(MAX_BLOB_BYTES + 1).unwrap()];
            write_put_blob(&mut Vec::new(), fixtures::digest(1), &oversized).unwrap_err()
        }
    }
}

#[test]
fn agent_error_kinds_cover_every_variant() {
    assert_kinds(AgentErrorKind::ALL, |kind| {
        fixtures::agent_error(kind).kind()
    });
}

#[test]
fn value_error_kinds_are_reachable_through_the_api() {
    assert_kinds(ValueErrorKind::ALL, |kind| value_error(kind).kind());
}

#[test]
fn read_error_kinds_are_reachable_through_the_api() {
    assert_kinds(ReadErrorKind::ALL, |kind| read_error(kind).kind());
}

#[test]
fn write_error_kinds_cover_every_variant() {
    assert_kinds(WriteErrorKind::ALL, |kind| write_error(kind).kind());
}

#[test]
fn watch_error_kinds_cover_every_variant() {
    assert_kinds(WatchErrorKind::ALL, |kind| {
        fixtures::watch_error(kind).kind()
    });
}

#[test]
fn every_agent_error_survives_the_wire() {
    for kind in AgentErrorKind::ALL {
        let error = fixtures::agent_error(*kind);
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(
            serde_json::from_str::<AgentError>(&json).unwrap(),
            error,
            "{json}"
        );
    }
    for kind in WatchErrorKind::ALL {
        let error = fixtures::watch_error(*kind);
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(
            serde_json::from_str::<WatchError>(&json).unwrap(),
            error,
            "{json}"
        );
    }
}

#[test]
fn every_read_error_maps_to_an_agent_error() {
    let expected = [
        (ReadErrorKind::Io, AgentErrorKind::Io),
        (ReadErrorKind::Sink, AgentErrorKind::Io),
        (ReadErrorKind::Empty, AgentErrorKind::UnknownRequest),
        (ReadErrorKind::Unterminated, AgentErrorKind::UnknownRequest),
        (ReadErrorKind::TooLarge, AgentErrorKind::RequestTooLarge),
        (ReadErrorKind::Malformed, AgentErrorKind::UnknownRequest),
        (ReadErrorKind::BlobTruncated, AgentErrorKind::BlobTruncated),
        (ReadErrorKind::TrailingBytes, AgentErrorKind::TrailingInput),
    ];
    assert_eq!(expected.map(|(kind, _)| kind), ReadErrorKind::ALL);
    for (read_kind, agent_kind) in expected {
        assert_eq!(
            read_error(read_kind).to_agent_error().kind(),
            agent_kind,
            "{read_kind:?}"
        );
    }
}

#[test]
fn every_response_answers_exactly_one_request_and_every_request_has_an_answer() {
    let mut answered = BTreeSet::new();
    for kind in ResponseKind::ALL {
        let response: Response = fixtures::response(*kind);
        assert_eq!(response.kind(), *kind);
        let answers: Vec<_> = RequestKind::ALL
            .iter()
            .filter(|request| response.answers(**request))
            .collect();
        assert_eq!(answers, [&kind.request()], "{kind:?}");
        answered.insert(kind.request());
    }
    assert_eq!(answered.into_iter().collect::<Vec<_>>(), RequestKind::ALL);
    assert!(fixtures::response(ResponseKind::Unchanged).answers(RequestKind::Apply));
    assert!(fixtures::response(ResponseKind::TxnLaunched).answers(RequestKind::Apply));
    assert!(!fixtures::response(ResponseKind::Confirmed).answers(RequestKind::ActivateAgent));
}

#[test]
fn every_txn_state_survives_the_wire() {
    for state in fixtures::txn_states() {
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<mooring_agent_proto::TxnState>(&json).unwrap(),
            state,
            "{json}"
        );
    }
}

#[test]
fn a_received_tail_is_checked_when_decoded() {
    for bad in [
        "\"line\\nbreak\"".to_owned(),
        format!("\"{}\"", "x".repeat(4097)),
    ] {
        let error = serde_json::from_str::<StderrTail>(&bad).unwrap_err();
        assert_eq!(error.to_string(), ValueError::StderrTail.to_string());
    }
    assert!(serde_json::from_str::<StderrTail>("\"fine\"").is_ok());
}
