// SPDX-License-Identifier: GPL-3.0-or-later

// The history mirror against the Rust-generated fixture
// (`contract/history-fixtures/radio.json`): what it reads, that every kind
// of event is read once, and that it refuses what the Rust types refuse.

import Foundation
import Testing

@testable import MooringKit

@Suite struct HistoryDecodingTests {
    private func fixture() throws -> Data {
        try Fixtures.data("contract/history-fixtures/radio.json")
    }

    @Test func theFixtureReadsAsTheRustBuilderMadeIt() throws {
        let history = try RadioHistory.decode(line: try fixture())
        #expect(history.since == CalendarDate("2026-10-12"))
        #expect(history.until == CalendarDate("2026-10-13"))
        #expect(history.incompleteDays == [CalendarDate("2026-10-13")])
        #expect(history.samples.count == 9)
        #expect(history.events.count == 10)
        // 2026-10-13 19:00:00 UTC, then one a minute.
        #expect(history.samples[0].at == UnixTime(seconds: 1_791_918_000))
        #expect(history.samples[8].at == UnixTime(seconds: 1_791_918_480))
        guard case .read(let first) = history.samples[0].poll, case .attached(let radio) = first.radio else {
            Issue.record("the first sample is not an attached read")
            return
        }
        #expect(first.uptimeSecs == 523_014)
        #expect(first.temperatureC == 44)
        #expect(first.thermal == .normal)
        #expect(radio.networkService == .nr5g)
        #expect(radio.dataService == .nrSub6)
        #expect(radio.band == .lte(3))
        #expect(radio.caSecondaryCount == 0)
        #expect(radio.lte.rsrp == -1000 && radio.lte.sinr == 20)
        #expect(radio.nr.rsrp == -905 && radio.nr.rsrq == -105 && radio.nr.sinr == 155)
        #expect(radio.plmn.mcc == "234" && radio.plmn.mnc == "30")
        #expect(radio.sessionSecs == 86_400)
        #expect(history.samples[0].attachment == radio)
        #expect(history.samples[1].poll == .failed(.unreachable))
        #expect(history.samples[1].attachment == nil)
        guard case .read(let fifth) = history.samples[4].poll else {
            Issue.record("the fifth sample is not a read")
            return
        }
        #expect(fifth.radio == .noService)
        #expect(history.samples[4].attachment == nil)
        #expect(
            history.events.map(\.kind) == [
                .pollFailed(.unreachable),
                .pollRecovered,
                .networkServiceChanged(from: .nr5g, to: .lte),
                .dataServiceChanged(from: .nrSub6, to: .ltePlus),
                .bandChanged(from: .lte(3), to: .lte(20)),
                .serviceLost,
                .serviceRegained,
                .sessionRestarted,
                .plmnChanged(from: history.samples[0].attachment!.plmn, to: history.samples[8].attachment!.plmn),
                .routerRebooted,
            ])
        #expect(history.events[0].at == UnixTime(seconds: 1_791_918_060))
        #expect(history.events[9].at == history.samples[8].at)
    }

    /// Every kind of event is read from the fixture, each once: a case
    /// added on either side fails here (the switch is exhaustive).
    @Test func everyEventKindIsReadOnce() throws {
        let history = try RadioHistory.decode(line: try fixture())
        let numbers = history.events.map { event -> Int in
            switch event.kind {
            case .pollFailed: 0
            case .pollRecovered: 1
            case .routerRebooted: 2
            case .serviceLost: 3
            case .serviceRegained: 4
            case .networkServiceChanged: 5
            case .dataServiceChanged: 6
            case .bandChanged: 7
            case .plmnChanged: 8
            case .sessionRestarted: 9
            }
        }
        #expect(Set(numbers).count == 10)
        #expect(numbers.count == 10)
    }

    /// Every object of the document refuses an unknown key, as the Rust
    /// types' `deny_unknown_fields` promises.
    @Test func everyObjectRefusesAnUnknownKey() throws {
        let json = try Fixtures.json(try fixture())
        let paths = JsonEdits.objectPaths(json)
        #expect(paths.count > 20)
        for path in paths {
            let edited = JsonEdits.inserting(into: json, at: path)
            #expect(throws: (any Error).self, "\(path)") {
                try RadioHistory.decode(line: try Fixtures.encode(edited))
            }
        }
    }

    /// Another version, a value outside its vocabulary, a variant in the
    /// other form than its own, and a missing key are refused.
    @Test func closedValuesAndAnotherVersionAreRefused() throws {
        let text = String(decoding: try fixture(), as: UTF8.self)
        let later = text.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2")
        #expect(throws: ConsoleDecodingError.unsupportedVersion(2)) {
            try RadioHistory.decode(line: Data(later.utf8))
        }
        for (from, to) in [
            ("\"nr5g\"", "\"lte5\""),
            ("\"band\": \"B3\"", "\"band\": \"B03\""),
            ("\"radio\": \"no_service\"", "\"radio\": {\"no_service\": null}"),
            ("\"kind\": \"poll_recovered\"", "\"kind\": {\"poll_recovered\": null}"),
            ("\"reason\": \"unreachable\"", "\"reason\": \"cell_id\""),
            ("\"thermal\": \"normal\"", "\"thermal\": \"hot\""),
        ] {
            let edited = text.replacingOccurrences(of: from, with: to)
            #expect(edited != text, Comment(rawValue: from))
            #expect(throws: (any Error).self, Comment(rawValue: from)) {
                try RadioHistory.decode(line: Data(edited.utf8))
            }
        }
        var object = try Fixtures.json(try fixture()) as! [String: Any]
        object.removeValue(forKey: "incomplete_days")
        #expect(throws: (any Error).self) {
            try RadioHistory.decode(line: try Fixtures.encode(object))
        }
    }

    /// The last 24 hours are a filter on the samples' times, which the
    /// Router screen applies to the CLI's default two days.
    @Test func theWindowIsAFilterOnTheSamplesTimes() throws {
        let history = try RadioHistory.decode(line: try fixture())
        let since = UnixTime(seconds: 1_791_918_120)
        #expect(history.samples(since: since).count == 7)
        #expect(history.samples(since: since).first?.at == since)
        #expect(history.events(since: since).count == 9)
        #expect(history.samples(since: UnixTime(seconds: 1_791_918_481)).isEmpty)
    }
}
