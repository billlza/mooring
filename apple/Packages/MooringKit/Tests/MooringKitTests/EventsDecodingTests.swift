// SPDX-License-Identifier: GPL-3.0-or-later

// The event journals' mirror against the Rust-generated fixture
// (`contract/events-fixtures/events.json`): what it reads, that every
// variant of every enum the journals carry is read, that a status's exit
// state gives the phase the Mac's journal keeps, that it refuses what the
// Rust types refuse, and the order the Events screen lists the entries in.

import Foundation
import Testing

@testable import MooringKit

@Suite struct EventsDecodingTests {
    /// 2026-11-15 00:00 UTC, the fixture's day.
    private static let day: UInt64 = 1_794_700_800

    private func fixture() throws -> Data {
        try Fixtures.data("contract/events-fixtures/events.json")
    }

    private func document() throws -> EventsDocument {
        try EventsDocument.decode(line: try fixture())
    }

    @Test func theFixtureReadsAsTheRustBuilderMadeIt() throws {
        let document = try document()
        #expect(document.since == CalendarDate("2026-11-15"))
        #expect(document.until == CalendarDate("2026-11-15"))
        #expect(document.omitted == 0)
        #expect(document.incompleteDays.map(\.node) == [nil, NodeId("lon1")])
        #expect(document.incompleteDays.map(\.day) == [CalendarDate("2026-11-15"), CalendarDate("2026-11-15")])
        try #require(document.entries.count == 85)
        guard case .mac(let first) = document.entries[0] else {
            Issue.record("the first entry is not the Mac's")
            return
        }
        #expect(first.at == UnixTime(seconds: Self.day))
        #expect(first.kind == .daemonStarted)
        #expect(document.entries[0].at == first.at)
        // A node's event is dated by the node's clock, a gap and a reset by
        // the Mac's read.
        guard case .node(let node, let line) = document.entries[43], case .event(let event) = line.entry else {
            Issue.record("entry 43 is not a node's event")
            return
        }
        #expect(node == NodeId("lon1"))
        #expect(line.readAt == UnixTime(seconds: 1_794_705_780))
        #expect(event.seq == 2)
        #expect(event.at == UnixTime(seconds: 1_794_703_380))
        #expect(event.kind == .conditionRaised(.wgReadFailed))
        #expect(document.entries[43].at == event.at)
        guard case .node(_, let gap) = document.entries[83], case .node(_, let reset) = document.entries[84] else {
            Issue.record("the last two entries are not a node's")
            return
        }
        #expect(gap.entry == .gap(from: 0, to: 2))
        #expect(reset.entry == .reset(end: 42))
        #expect(document.entries[83].at == UnixTime(seconds: 1_794_705_780))
        #expect(reset.at == reset.readAt)
        #expect(zip(document.entries, document.entries.dropFirst()).allSatisfy { $0.at <= $1.at })
    }

    /// Every variant of every enum the journals carry is read from the
    /// fixture: a case added on either side fails here (the switches are
    /// exhaustive, and each list is the Swift cases in order).
    @Test func everyVariantIsRead() throws {
        var mac: [Int] = []
        var phases: [Int] = []
        var power: [PowerSource] = []
        var drains: [DrainOutcome] = []
        var degraded: [[DegradedReasonKind]] = []
        var down: [DownReasonKind] = []
        var causes: [AgentUnreachable] = []
        var lines: [Int] = []
        var kinds: [Int] = []
        var numbers: [UInt64] = []
        var raised: [WatchError] = []
        var cleared: [WatchErrorKind] = []
        var recorded: [GateReason] = []
        var released: [GateReason] = []
        var halts: [ShutdownReason] = []
        var engines: [EngineUser] = []
        var generations: [UInt64] = []
        for entry in try document().entries {
            switch entry {
            case .mac(let event):
                switch event.kind {
                case .daemonStarted: mac.append(0)
                case .powerSource(let source):
                    mac.append(1)
                    power.append(source)
                case .slept(let drain):
                    mac.append(2)
                    drains.append(drain)
                case .woke: mac.append(3)
                case .exit(let phase):
                    mac.append(4)
                    switch phase {
                    case .disabled: phases.append(0)
                    case .preflight: phases.append(1)
                    case .starting: phases.append(2)
                    case .verifying: phases.append(3)
                    case .serving: phases.append(4)
                    case .degraded(let reasons):
                        phases.append(5)
                        degraded.append(reasons)
                    case .down(let reason):
                        phases.append(6)
                        down.append(reason)
                    case .paused: phases.append(7)
                    }
                case .nodeUnreachable(_, let cause):
                    mac.append(5)
                    causes.append(cause)
                case .nodeReachable: mac.append(6)
                }
            case .node(_, let line):
                switch line.entry {
                case .event(let event):
                    lines.append(0)
                    numbers.append(event.seq)
                    switch event.kind {
                    case .conditionRaised(let condition):
                        kinds.append(0)
                        raised.append(condition)
                    case .conditionCleared(let condition):
                        kinds.append(1)
                        cleared.append(condition)
                    case .gateOpened: kinds.append(2)
                    case .gateClosed: kinds.append(3)
                    case .holdRecorded(let hold):
                        kinds.append(4)
                        recorded.append(hold)
                    case .holdCleared(let hold):
                        kinds.append(5)
                        released.append(hold)
                    case .halted(let reason):
                        kinds.append(6)
                        halts.append(reason)
                    case .resumed(let generation):
                        kinds.append(7)
                        generations.append(generation)
                    case .committed(let generation):
                        kinds.append(8)
                        generations.append(generation)
                    case .engineRestarted(let engine):
                        kinds.append(9)
                        engines.append(engine)
                    case .hostBooted: kinds.append(10)
                    }
                case .gap: lines.append(1)
                case .reset: lines.append(2)
                }
            }
        }
        #expect(Set(mac) == Set(0..<7))
        #expect(Set(phases) == Set(0..<8))
        #expect(power == PowerSource.allCases)
        #expect(drains == DrainOutcome.allCases)
        #expect(degraded == [DegradedReasonKind.allCases])
        #expect(down == DownReasonKind.allCases)
        #expect(causes == AgentUnreachable.allCases)
        #expect(Set(lines) == Set(0..<3))
        #expect(Set(kinds) == Set(0..<11))
        #expect(numbers == Array(2...41))
        #expect(
            raised == [
                .wgReadFailed, .nftFailed, .statsQueryFailed, .targetDegraded, .targetReadFailed(errno: 13),
                .exitFlowCapHit(count: 14), .stateWrite(errno: 28), .macSilent(since: UnixTime(seconds: 1_791_416_400)),
                .diskLow(free: 950_000_000), .clockUnsynced, .rebootPending(since: UnixTime(seconds: 1_791_331_200)),
                .accountingCanaryMissing(inbounds: [.reality, .hy2]),
            ])
        #expect(cleared == WatchErrorKind.allCases)
        #expect(recorded == GateReason.allCases)
        #expect(released == GateReason.allCases)
        #expect(halts == ShutdownReason.allCases)
        #expect(engines == EngineUser.allCases)
        #expect(EngineUser.allCases.map(\.engine) == NodeEngine.allCases)
        #expect(generations == [7, 8])
    }

    /// A status's exit state gives the phase the Mac's journal keeps: the
    /// status fixture's reasons, which the Rust tests list in the order of
    /// the journal fixture's, have the Rust types' kinds, and a degraded
    /// state keeps each kind once, in the order the kinds are declared.
    @Test func anExitStatesPhaseIsTheJournals() throws {
        let variants = try #require(
            try Fixtures.json(try Fixtures.data("contract/status-fixtures/variants.json")) as? [String: Any])
        func decode<T: Decodable>(_ type: T.Type, _ key: String) throws -> [T] {
            try JSONDecoder().decode([T].self, from: try Fixtures.encode(try #require(variants[key])))
        }
        #expect(
            try decode(ExitState.self, "exit_state").map(\.phase) == [
                .disabled, .preflight, .starting, .verifying, .serving,
                .degraded(reasons: DegradedReasonKind.allCases), .down(reason: .secretsUnavailable), .paused,
            ])
        let journal = try document().entries.compactMap { entry -> DownReasonKind? in
            if case .mac(let event) = entry, case .exit(.down(let reason)) = event.kind {
                return reason
            }
            return nil
        }
        #expect(try decode(DownReason.self, "down_reason").map(\.kind) == journal)
        #expect(try decode(DegradedReason.self, "degraded_reason").map(\.kind) == DegradedReasonKind.allCases)
        let twice = ExitState.degraded(reasons: [
            .onBattery, .watchStale(node: NodeId("lon1")), .watchStale(node: NodeId("ams1")),
        ])
        #expect(twice.phase == .degraded(reasons: [.watchStale, .onBattery]))
    }

    /// Every object of the document refuses an unknown key, as the Rust
    /// types' `deny_unknown_fields` promises.
    @Test func everyObjectRefusesAnUnknownKey() throws {
        let json = try Fixtures.json(try fixture())
        let objects = try JSONPaths.expectEveryObjectRefusesAnUnknownKey(in: json) {
            _ = try EventsDocument.decode(line: $0)
        }
        #expect(objects == 509)
    }

    /// Every key of every object of the document is required, the `null`
    /// of the Mac's incomplete day too, as the Rust types require it.
    @Test func everyKeyIsRequired() throws {
        let json = try Fixtures.json(try fixture())
        let (removed, nulls) = try JSONPaths.expectEveryKeyIsRequired(in: json) {
            _ = try EventsDocument.decode(line: $0)
        }
        #expect(removed == 733)
        #expect(nulls == 1)
    }

    /// Another version, a value outside its vocabulary, a variant in the
    /// other form than its own, an entry of no journal and an empty gap
    /// are refused.
    @Test func closedValuesAndAnotherVersionAreRefused() throws {
        let text = String(decoding: try fixture(), as: UTF8.self)
        let later = text.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2")
        #expect(throws: ConsoleDecodingError.unsupportedVersion(2)) {
            try EventsDocument.decode(line: Data(later.utf8))
        }
        for (from, to) in [
            ("\"kind\": \"daemon_started\"", "\"kind\": {\"daemon_started\": null}"),
            ("\"kind\": \"GateOpened\"", "\"kind\": {\"GateOpened\": null}"),
            ("\"phase\": \"paused\"", "\"phase\": \"asleep\""),
            ("\"reason\": \"EgressInterfaceAbsent\"", "\"reason\": \"egress_interface_absent\""),
            ("\"cause\": \"spawn\"", "\"cause\": \"Spawn\""),
            ("\"engine\": \"Xray\"", "\"engine\": \"xray\""),
            ("\"hold\": \"MacDrain\"", "\"hold\": \"mac_drain\""),
            ("\"condition\": \"WgReadFailed\"", "\"condition\": \"wg_read_failed\""),
            ("\"gap\": {", "\"skip\": {"),
            ("\"mac\": {", "\"Mac\": {"),
            ("\"node\": null", "\"node\": 0"),
            ("\"to\": 2", "\"to\": 0"),
        ] {
            let edited = text.replacingOccurrences(of: from, with: to)
            #expect(edited != text, Comment(rawValue: from))
            #expect(throws: (any Error).self, Comment(rawValue: from)) {
                try EventsDocument.decode(line: Data(edited.utf8))
            }
        }
    }

    /// The Events screen lists the entries by the day of their time in the
    /// user's calendar: the newest day first, and in each day the newest
    /// entry first, entries of one time in the reverse of the document's
    /// order.
    @Test func theEntriesAreListedByDayNewestFirst() throws {
        let document = try document()
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = try #require(TimeZone(identifier: "UTC"))
        let one = document.days(in: utc)
        try #require(one.count == 1)
        #expect(one[0].start == Date(timeIntervalSince1970: TimeInterval(Self.day)))
        #expect(one[0].entries == document.entries.reversed())
        // An hour west of UTC, the day's first hour falls on the day before.
        var west = Calendar(identifier: .gregorian)
        west.timeZone = try #require(TimeZone(secondsFromGMT: -3600))
        let two = document.days(in: west)
        try #require(two.count == 2)
        let midnight = UnixTime(seconds: Self.day + 3600)
        #expect(two[0].start == midnight.date)
        #expect(two[0].entries == document.entries.filter { $0.at >= midnight }.reversed())
        #expect(two[1].start == UnixTime(seconds: Self.day + 3600 - 86_400).date)
        #expect(two[1].entries == document.entries.filter { $0.at < midnight }.reversed())
        #expect(two[0].entries.first?.at == UnixTime(seconds: 1_794_705_780))
        guard case .node(_, let newest) = two[0].entries[0], case .node(_, let next) = two[0].entries[1] else {
            Issue.record("the newest entries are not a node's")
            return
        }
        #expect(newest.entry == .reset(end: 42))
        #expect(next.entry == .gap(from: 0, to: 2))
        let empty = try EventsDocument.decode(
            line: Data(
                #"{"version":1,"since":"2026-11-09","until":"2026-11-15","entries":[],"omitted":0,"incomplete_days":[]}"#
                    .utf8))
        #expect(empty.days(in: utc).isEmpty)
    }
}
