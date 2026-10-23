// SPDX-License-Identifier: GPL-3.0-or-later

// The mirror of a deployment's status against the Rust-generated fixtures
// (`contract/status-fixtures/`, design §15.2): what it reads from the
// three scenarios, and that it refuses what the Rust types refuse: an
// unknown key anywhere, a missing key (a `null` included), another
// version.

import Foundation
import Testing

@testable import MooringKit

@Suite struct DeployedDecodingTests {
    static let scenarios = ["serving", "degraded", "down"]

    private func scenario(_ name: String) throws -> Data {
        try Fixtures.data("contract/status-fixtures/\(name).json")
    }

    private func decode(_ data: Data) throws -> DeployedStatus {
        try JSONDecoder().decode(DeployedStatus.self, from: data)
    }

    @Test func theServingScenarioReadsAsTheRustBuilderMadeIt() throws {
        let status = try decode(try scenario("serving"))
        guard case .serving(let ip, let verifiedAt) = status.exit.state else {
            Issue.record("not serving: \(status.exit.state)")
            return
        }
        #expect(ip == status.exit.carrierCheck?.egressIp)
        #expect(verifiedAt <= status.at)
        #expect(status.exit.latches.isEmpty)
        #expect(status.exit.egress?.link.up == true)
        #expect(status.exit.carrierCheck?.inCarrierPrefixes == true)
        #expect(status.exit.carrierCheck?.pairing == .paired)
        #expect(status.exit.engines.exit.pid != nil)
        #expect(status.exit.power.source == .ac)
        #expect(status.exit.foreignNetworks.isEmpty)
        #expect(status.sim.accuracy == .exact)
        guard case .hardStop = status.sim.thresholds.stop else {
            Issue.record("not a hard stop: \(status.sim.thresholds.stop)")
            return
        }
        guard case .projected(let forecast) = status.sim.forecast else {
            Issue.record("no forecast: \(status.sim.forecast)")
            return
        }
        #expect(forecast.cycle == status.sim.cycle)
        #expect(forecast.usedBytes == status.sim.rxBytes + status.sim.txBytes)
        #expect(forecast.crossings.map(\.threshold) == [.warn, .hardStop])
        guard case .available = status.router else {
            Issue.record("the router is not available")
            return
        }
        #expect(status.advisories == [])
        #expect(status.capacity != nil)
        guard case .report(let periods) = status.usage else {
            Issue.record("no usage report: \(status.usage)")
            return
        }
        #expect(periods.cycle == status.sim.cycle)
        #expect(status.users.count == 3)
        #expect(status.users.values.allSatisfy { $0.usage != nil })
        #expect(status.sortedNodes.map(\.id.text) == ["ams1", "lon1"])
        for (id, row) in status.sortedNodes {
            guard case .reported(let report) = row.agent else {
                Issue.record("\(id.text) is not reported: \(row.agent)")
                continue
            }
            #expect(report.gate == .open, "\(id.text)")
            #expect(row.verdicts.reality?.outcome == .verified, "\(id.text)")
            #expect(row.verdicts.hy2?.outcome == .verified, "\(id.text)")
        }
    }

    @Test func theDegradedScenarioCarriesItsReasonsAndAlerts() throws {
        let status = try decode(try scenario("degraded"))
        guard case .degraded(let reasons) = status.exit.state else {
            Issue.record("not degraded: \(status.exit.state)")
            return
        }
        #expect(!reasons.isEmpty)
        #expect(status.users.count == 20)
        #expect(!status.alerts.isEmpty)
        #expect(
            status.alerts.contains {
                if case .simForecastCrossing = $0.condition { true } else { false }
            })
        #expect(
            status.alerts.contains {
                if case .exitDegraded = $0.condition { true } else { false }
            })
    }

    @Test func theDownScenarioSaysWhyWithoutFigures() throws {
        let status = try decode(try scenario("down"))
        guard case .down(.violation(.egressMismatch(let d1, let d2, let observed))) = status.exit.state
        else {
            Issue.record("not down for an egress mismatch: \(status.exit.state)")
            return
        }
        #expect(d1 == d2 && observed != d1)
        #expect(status.exit.latches.map(\.violation.kind) == [.egressMismatch])
        #expect(status.capacity == nil)
        #expect(status.usage == .unavailable(reason: .notCoveredThrough))
        #expect(status.users.values.allSatisfy { $0.usage == nil })
        guard case .unavailable = status.router else {
            Issue.record("the router is available")
            return
        }
        #expect(status.advisories == [])
    }

    /// Every object of every scenario refuses an unknown key; in a map (the
    /// users, the nodes, per-node figures) the key reads as an entry whose
    /// value is refused.
    @Test(arguments: scenarios)
    func everyObjectRefusesAnUnknownKey(_ name: String) throws {
        let json = try Fixtures.json(try scenario(name))
        _ = try decode(try Fixtures.encode(json))
        let paths = JSONPaths.objects(json)
        #expect(paths.count >= 40)
        for path in paths {
            let edited = JSONPaths.editing(json, at: path) { object in
                var object = object
                object["zz_unknown"] = true
                return object
            }
            #expect(throws: (any Error).self, "accepted an unknown key at \(path)") {
                try decode(try Fixtures.encode(edited))
            }
        }
    }

    /// Every key of every object is required, a `null` too, except in the
    /// maps, whose entries are the deployment's own.
    @Test(arguments: scenarios)
    func everyKeyIsRequired(_ name: String) throws {
        let json = try Fixtures.json(try scenario(name))
        var removed = 0
        var nulls = 0
        for path in JSONPaths.objects(json, skippingMaps: Self.maps) {
            guard let object = JSONPaths.value(json, at: path) as? [String: Any] else {
                continue
            }
            for key in object.keys.sorted() {
                removed += 1
                if object[key] is NSNull {
                    nulls += 1
                }
                let edited = JSONPaths.editing(json, at: path) { object in
                    var object = object
                    object.removeValue(forKey: key)
                    return object
                }
                #expect(throws: (any Error).self, "accepted a missing \(key) at \(path)") {
                    try decode(try Fixtures.encode(edited))
                }
            }
        }
        #expect(removed >= 100)
        #expect(nulls >= 3)
    }

    /// The JSON objects that are maps keyed by the deployment's ids, not
    /// records with fixed keys.
    static let maps: Set<String> = ["users", "nodes", "by_node", "cycle_by_node"]

    @Test func anotherVersionIsRefusedAsSuch() throws {
        let line = String(decoding: try scenario("serving"), as: UTF8.self)
        #expect(throws: ConsoleDecodingError.unsupportedVersion(2)) {
            try decode(Data(line.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2").utf8))
        }
    }

    /// A variant in the other form than its own is refused: a unit variant
    /// is a string, any other an object with one key.
    @Test func variantsKeepTheirForm() throws {
        for refused in [
            "\"serving\"", "{\"disabled\": null}", "{\"disabled\": {}}", "{\"paused\": {}}",
            "{\"down\": {\"reason\": \"egress_ambiguous\"}}", "\"degraded\"",
            "{\"serving\": {\"ip\": \"192.0.2.1\"}}",
            "{\"serving\": {\"ip\": \"192.0.2.1\", \"verified_at\": 1, \"since\": 1}}",
            "{\"disabled\": 1, \"paused\": 1}",
        ] {
            #expect(throws: (any Error).self, "\(refused)") {
                try JSONDecoder().decode(ExitState.self, from: Data(refused.utf8))
            }
        }
        #expect(try JSONDecoder().decode(ExitState.self, from: Data("\"paused\"".utf8)) == .paused)
        #expect(
            try JSONDecoder().decode(EngineRun.self, from: Data("\"Inactive\"".utf8)) == .inactive)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(EngineRun.self, from: Data("\"inactive\"".utf8))
        }
    }
}

/// Paths into a JSON value read with `JSONSerialization`, and edits at
/// them.
enum JSONPaths {
    /// The path (keys and indices) of every object in `value`; with
    /// `skippingMaps`, the objects under those keys are left out, though
    /// the objects inside their entries are kept.
    static func objects(_ value: Any, skippingMaps maps: Set<String> = [], _ path: [Any] = [])
        -> [[Any]]
    {
        if let object = value as? [String: Any] {
            let isMap = (path.last as? String).map(maps.contains) ?? false
            let inner = object.keys.sorted().flatMap { key in
                objects(object[key] as Any, skippingMaps: maps, path + [key])
            }
            return isMap ? inner : [path] + inner
        }
        if let array = value as? [Any] {
            return array.indices.flatMap { objects(array[$0], skippingMaps: maps, path + [$0]) }
        }
        return []
    }

    /// The value at `path`.
    static func value(_ value: Any, at path: [Any]) -> Any? {
        guard let head = path.first else {
            return value
        }
        let rest = Array(path.dropFirst())
        if let key = head as? String, let object = value as? [String: Any], let inner = object[key] {
            return Self.value(inner, at: rest)
        }
        if let index = head as? Int, let array = value as? [Any], array.indices.contains(index) {
            return Self.value(array[index], at: rest)
        }
        return nil
    }

    /// `value` with the object at `path` replaced by `edit`'s result.
    static func editing(_ value: Any, at path: [Any], _ edit: ([String: Any]) -> [String: Any]) -> Any {
        guard let head = path.first else {
            return edit(value as? [String: Any] ?? [:])
        }
        let rest = Array(path.dropFirst())
        if let key = head as? String, var object = value as? [String: Any] {
            object[key] = editing(object[key] as Any, at: rest, edit)
            return object
        }
        if let index = head as? Int, var array = value as? [Any] {
            array[index] = editing(array[index], at: rest, edit)
            return array
        }
        return value
    }
}
