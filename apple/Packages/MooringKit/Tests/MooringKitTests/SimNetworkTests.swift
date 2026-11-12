// SPDX-License-Identifier: GPL-3.0-or-later

// The SIM's network in a deployment's status (`sim.network`, design §10.2,
// §15.2): what the three scenarios carry, the change the console shows
// (`SimNetworkStatus.change`) and what it differs in, and that the mirror
// refuses a baseline that is its own other network. On 2026-11-12 the
// carrier check and the cycle on record were those of a SIM taken out the
// day before, and nothing on the console said so.

import Foundation
import Testing

@testable import MooringKit

@Suite struct SimNetworkTests {
    private func scenario(_ name: String) throws -> SimNetworkStatus {
        let data = try Fixtures.data("contract/status-fixtures/\(name).json")
        return try JSONDecoder().decode(DeployedStatus.self, from: data).sim.network
    }

    private func decode(_ text: String) throws -> SimNetworkStatus {
        try JSONDecoder().decode(SimNetworkStatus.self, from: Data(text.utf8))
    }

    /// A network's JSON: the SIM's name, or `null` without one, on 234
    /// and `mnc`.
    private func network(_ spn: String?, _ mnc: String) -> String {
        let name = spn.map { "\"\($0)\"" } ?? "null"
        return "{\"spn\": \(name), \"plmn\": {\"mcc\": \"234\", \"mnc\": \"\(mnc)\"}}"
    }

    /// A status whose baseline is `recorded`, first seen at 100, with
    /// `reported` since 200.
    private func changed(from recorded: String, to reported: String) -> String {
        """
        {"origin": "recorded", "baseline": {"network": \(recorded), "first_seen": 100,
         "other": {"network": \(reported), "since": 200}}}
        """
    }

    /// The baseline is the SIM without a name the M7 reported, and the M7
    /// still reports it: nothing to show.
    @Test func theServingScenarioHoldsItsBaselineAndNoChange() throws {
        let status = try scenario("serving")
        #expect(status.origin == .recorded)
        let baseline = try #require(status.baseline)
        #expect(baseline.network.spn == nil)
        #expect(baseline.network.plmn.mcc == "234")
        #expect(baseline.network.plmn.mnc == "20")
        #expect(baseline.firstSeen.seconds == 1_790_845_200)
        #expect(baseline.other == nil)
        #expect(status.change == nil)
    }

    /// The M7 reports a SIM without a name where the baseline is CMLink's:
    /// the change carries both, when the baseline was taken and since when
    /// the M7 reports the other.
    @Test func theDegradedScenarioHoldsAnotherSimSinceItWasFirstReported() throws {
        let status = try scenario("degraded")
        #expect(status.origin == .noRecord)
        let baseline = try #require(status.baseline)
        let change = try #require(status.change)
        #expect(change.recorded == baseline.network)
        #expect(change.recorded.spn == "CMLink")
        #expect(change.recorded.plmn.mnc == "30")
        #expect(change.recordedAt.seconds == 1_790_845_200)
        #expect(change.reported == baseline.other?.network)
        #expect(change.reported.spn == nil)
        #expect(change.reported.plmn.mnc == "20")
        #expect(change.since.seconds == 1_791_398_400)
        #expect(change.difference == .simName)
    }

    /// The record could not be read and no poll has given a baseline since.
    @Test func theDownScenarioHasNoBaselineAndSaysWhy() throws {
        let status = try scenario("down")
        #expect(status.origin == .recordUnreadable)
        #expect(status.baseline == nil)
        #expect(status.change == nil)
    }

    /// Another name, or a name where there was none or none where there
    /// was one, is another SIM whatever the codes; the same name, or none
    /// both times, on other codes differs in the network alone.
    @Test func aChangeDiffersInTheSimsNameOrInTheNetworkAlone() throws {
        let cases: [(String?, String, String?, String, NetworkDifference)] = [
            ("CMLink", "30", "1p", "30", .simName),
            ("CMLink", "30", "1p", "20", .simName),
            (nil, "20", "1p", "30", .simName),
            (nil, "20", "1p", "20", .simName),
            ("1p", "30", nil, "30", .simName),
            ("1p", "30", "1P", "30", .simName),
            ("1p", "30", "1p", "33", .networkOnly),
            (nil, "20", nil, "10", .networkOnly),
        ]
        for (recorded, recordedMnc, reported, reportedMnc, difference) in cases {
            let status = try decode(
                changed(from: network(recorded, recordedMnc), to: network(reported, reportedMnc)))
            let change = try #require(status.change, "\(recorded ?? "-") \(reported ?? "-")")
            #expect(change.difference == difference, "\(recorded ?? "-") \(recordedMnc) \(reported ?? "-") \(reportedMnc)")
            #expect(change.recorded.spn == recorded)
            #expect(change.recorded.plmn.mnc == recordedMnc)
            #expect(change.reported.spn == reported)
            #expect(change.reported.plmn.mnc == reportedMnc)
            #expect(change.recordedAt.seconds == 100)
            #expect(change.since.seconds == 200)
        }
        #expect(NetworkDifference.allCases == [.simName, .networkOnly])
    }

    /// The Rust type never holds the baseline's own network as the other
    /// one, and the mirror refuses it, so that every change differs in
    /// something; a `null` other and no baseline are read.
    @Test func aBaselineThatIsItsOwnOtherNetworkIsRefused() throws {
        for same in [network("1p", "30"), network(nil, "20")] {
            let error = #expect(throws: DecodingError.self) {
                try decode(changed(from: same, to: same))
            }
            guard case .dataCorrupted(let context)? = error else {
                Issue.record("not refused as corrupt: \(String(describing: error))")
                continue
            }
            #expect(context.debugDescription == "the other network is the baseline's own")
            #expect(context.codingPath.map(\.stringValue) == ["baseline", "other"])
        }
        let held = try decode(
            "{\"origin\": \"no_record\", \"baseline\": {\"network\": \(network("1p", "30")), \"first_seen\": 7, \"other\": null}}"
        )
        #expect(held.baseline?.firstSeen.seconds == 7)
        #expect(held.change == nil)
        #expect(try decode("{\"origin\": \"no_record\", \"baseline\": null}").change == nil)
    }

    /// Every key is required, a `null` too, and no other key is read.
    @Test func everyKeyOfTheNetworkIsRequiredAndNoOtherIsRead() throws {
        let whole = changed(from: network("CMLink", "30"), to: network(nil, "20"))
        let json = try Fixtures.json(Data(whole.utf8))
        let read: (Data) throws -> Void = { _ = try JSONDecoder().decode(SimNetworkStatus.self, from: $0) }
        let objects = try JSONPaths.expectEveryObjectRefusesAnUnknownKey(in: json, decode: read)
        #expect(objects == 7)
        let (removed, nulls) = try JSONPaths.expectEveryKeyIsRequired(in: json, decode: read)
        #expect(removed == 15)
        #expect(nulls == 1)
    }
}
