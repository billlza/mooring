// SPDX-License-Identifier: GPL-3.0-or-later

// The power helper's protocol against the Rust-generated fixture
// (`contract/power-fixtures/protocol.json`), and its logic over a recorder
// in place of IOKit.

import Foundation
import Testing

@testable import MooringPower

/// The repository's root: five levels above this file.
private let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()

/// The fixture's lists, each value as one compact line.
private func fixtureLines(_ key: String) throws -> [String] {
    let data = try Data(contentsOf: root.appendingPathComponent("contract/power-fixtures/protocol.json"))
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let list = object[key] as? [Any]
    else {
        throw CocoaError(.coderValueNotFound)
    }
    return try list.map { value in
        let line = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys])
        return String(decoding: line, as: UTF8.self) + "\n"
    }
}

@MainActor
private final class Recorder: PowerSystem {
    var powerSource: PowerSourceValue? = .ac
    var calls: [String] = []
    var failHold = false

    func readPowerSource() throws(PowerSystemError) -> PowerSourceValue {
        guard let powerSource else {
            throw PowerSystemError(call: "IOPSCopyPowerSourcesInfo", status: -1)
        }
        return powerSource
    }

    func holdAssertions() throws(PowerSystemError) {
        if failHold {
            throw PowerSystemError(call: "IOPMAssertionCreateWithName", status: -536_870_212)
        }
        calls.append("hold")
    }

    func releaseAssertions() {
        calls.append("release")
    }

    func allowSleep(token: Int) {
        calls.append("allow \(token)")
    }
}

@MainActor
@Suite struct PowerHelperTests {
    /// Every event the fixture lists is written exactly as Rust encodes it,
    /// and every command it lists is read.
    @Test func theFixturesLinesAreWrittenAndRead() throws {
        let events: [HelperEvent] = [
            .powerSource(.ac), .assertions(held: true), .willSleep(id: 7), .didWake,
        ]
        #expect(try fixtureLines("events") == events.map(\.line))
        var commands: [HelperCommand] = []
        for line in try fixtureLines("commands") {
            commands.append(try HelperCommand.decode(line: Data(line.utf8)))
        }
        #expect(commands == [.hold(true), .allowSleep(id: 7)])
        #expect(HelperEvent.powerSource(.battery).line == "{\"power_source\":\"battery\"}\n")
        #expect(HelperEvent.assertions(held: false).line == "{\"assertions\":{\"held\":false}}\n")
    }

    /// Anything but a known command, as the Rust side refuses it, is
    /// refused.
    @Test func otherLinesAreRefused() throws {
        for line in [
            "", "{}", "\"hold\"", "{\"hold\":1}", "{\"hold\":true,\"x\":1}", "{\"allow_sleep\":{}}",
            "{\"allow_sleep\":{\"id\":-1}}", "{\"allow_sleep\":{\"id\":1,\"x\":2}}", "{\"stop\":true}",
            "{\"hold\":true}\n{\"hold\":true}", "[1]",
        ] {
            #expect(throws: HelperCommand.Refusal.notACommand, "\(line)") {
                try HelperCommand.decode(line: Data(line.utf8))
            }
        }
        #expect(throws: HelperCommand.Refusal.tooLong) {
            try HelperCommand.decode(line: Data(repeating: 0x20, count: maxHelperLineBytes + 1))
        }
        #expect(try HelperCommand.decode(line: Data("{\"hold\":false}\n".utf8)) == .hold(false))
    }

    @Test func itHoldsAndReleasesAsTheDaemonSays() throws {
        let system = Recorder()
        var events: [HelperEvent] = []
        let helper = PowerHelper(system: system, emit: { events.append($0) }, report: { _ in })
        try helper.start()
        helper.handle(.hold(true))
        helper.handle(.hold(true))
        helper.handle(.hold(false))
        helper.handle(.hold(false))
        #expect(system.calls == ["hold", "release"])
        #expect(
            events == [
                .powerSource(.ac), .assertions(held: true), .assertions(held: true),
                .assertions(held: false), .assertions(held: false),
            ])
        // A hold IOKit refuses is reported, and the daemon told it is not held.
        system.failHold = true
        var reports: [String] = []
        let refused = PowerHelper(system: system, emit: { events.append($0) }, report: { reports.append($0) })
        refused.handle(.hold(true))
        #expect(!refused.holding)
        #expect(events.last == .assertions(held: false))
        #expect(reports == ["mooring-power: IOPMAssertionCreateWithName failed with -536870212"])
    }

    /// A sleep is held until the daemon answers it, or until its timeout;
    /// an answer for a sleep no longer held changes nothing.
    @Test func aSleepIsHeldUntilAnsweredOrTimedOut() {
        let system = Recorder()
        var events: [HelperEvent] = []
        let helper = PowerHelper(system: system, emit: { events.append($0) }, report: { _ in })
        let first = helper.willSleep(token: 41)
        #expect(first == 1)
        #expect(system.calls == [])
        helper.handle(.allowSleep(id: 1))
        #expect(system.calls == ["allow 41"])
        helper.handle(.allowSleep(id: 1))
        #expect(system.calls == ["allow 41"])
        let second = helper.willSleep(token: 42)
        helper.sleepTimedOut(id: second)
        helper.handle(.allowSleep(id: second))
        #expect(system.calls == ["allow 41", "allow 42"])
        helper.didWake()
        #expect(events == [.willSleep(id: 1), .willSleep(id: 2), .didWake])
    }

    @Test func aChangedPowerSourceIsReportedOnce() throws {
        let system = Recorder()
        var events: [HelperEvent] = []
        let helper = PowerHelper(system: system, emit: { events.append($0) }, report: { _ in })
        try helper.start()
        helper.powerSourceChanged()
        system.powerSource = .battery
        helper.powerSourceChanged()
        helper.powerSourceChanged()
        #expect(events == [.powerSource(.ac), .powerSource(.battery)])
        // A read that fails keeps the last source, and the log says why.
        var reports: [String] = []
        let logged = PowerHelper(system: system, emit: { events.append($0) }, report: { reports.append($0) })
        try logged.start()
        system.powerSource = nil
        logged.powerSourceChanged()
        #expect(events.last == .powerSource(.battery))
        #expect(reports == ["mooring-power: IOPSCopyPowerSourcesInfo failed with -1"])
        // And at the start, it fails the start.
        let failing = PowerHelper(system: system, emit: { events.append($0) }, report: { _ in })
        #expect(throws: PowerSystemError(call: "IOPSCopyPowerSourcesInfo", status: -1)) {
            try failing.start()
        }
    }

    /// At the daemon's end everything is released and held sleeps proceed.
    @Test func theEndOfInputReleasesEverything() {
        let system = Recorder()
        let helper = PowerHelper(system: system, emit: { _ in }, report: { _ in })
        helper.handle(.hold(true))
        _ = helper.willSleep(token: 9)
        helper.inputEnded()
        #expect(system.calls == ["hold", "release", "allow 9"])
        #expect(!helper.holding)
        helper.inputEnded()
        #expect(system.calls == ["hold", "release", "allow 9"])
    }
}
