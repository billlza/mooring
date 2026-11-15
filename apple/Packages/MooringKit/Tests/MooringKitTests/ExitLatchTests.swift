// SPDX-License-Identifier: GPL-3.0-or-later

// When the violation the exit is down for was found
// (`ExitSection.violationLatchedAt`): the time of the latch that carries
// it, never the state's `since`, which a daemon restart or another down
// reason in front of the latch moves. On 2026-11-12 the console showed a
// latch of two days before under that later time, and it read as a new
// event. And the latches the state does not show
// (`ExitSection.latchesBehindTheState`): for the day and a half before,
// the overview had named only the foreign network in front of that latch.

import Foundation
import Testing

@testable import MooringKit

@Suite struct ExitLatchTests {
    /// When the down scenario's one latch was written.
    static let latchedAt: UInt64 = 1_791_477_600

    /// The down scenario's exit section, down for an egress mismatch that
    /// its one latch carries, after `edit`.
    private func exit(_ edit: (inout [String: Any]) throws -> Void = { _ in }) throws -> ExitSection {
        let json = try Fixtures.json(try Fixtures.data("contract/status-fixtures/down.json"))
        let document = try #require(json as? [String: Any])
        var section = try #require(document["exit"] as? [String: Any])
        try edit(&section)
        return try JSONDecoder().decode(ExitSection.self, from: try Fixtures.encode(section))
    }

    /// The fixture's latch, with another time or another violation.
    private func latch(
        of section: [String: Any], at: UInt64, violation: [String: Any]? = nil
    ) throws -> [String: Any] {
        var latch = try #require((section["latches"] as? [[String: Any]])?.first)
        latch["at"] = at
        if let violation {
            latch["violation"] = violation
        }
        return latch
    }

    @Test func theFixtureIsDownForTheViolationItsLatchCarries() throws {
        let exit = try exit()
        guard case .down(.violation(let violation)) = exit.state else {
            Issue.record("not down for a violation: \(exit.state)")
            return
        }
        #expect(exit.latches.map(\.violation) == [violation])
        #expect(exit.latches.map(\.at.seconds) == [Self.latchedAt])
    }

    /// The state became what it is 36 h after the latch, as it does when
    /// another reason held the exit down in between or the daemon
    /// restarted: the violation was still found when its latch says.
    @Test func theLatchsTimeIsReadNotTheStatesSince() throws {
        let exit = try exit { $0["since"] = Self.latchedAt + 130_091 }
        #expect(exit.since.seconds == Self.latchedAt + 130_091)
        #expect(exit.violationLatchedAt?.seconds == Self.latchedAt)
    }

    /// A latch is on disk, but the exit is down for a reason the preflight
    /// checks before it (a foreign network), disabled or serving: the
    /// state shows no violation, so there is no time of one to show.
    @Test func aStateThatIsNoViolationHasNoLatchedTime() throws {
        let foreign: [String: Any] = [
            "down": [
                "reason": [
                    "foreign_network_attached": ["findings": [["routable_ipv4": ["interface": "en0"]]]]
                ]
            ]
        ]
        let serving: [String: Any] = ["serving": ["ip": "192.0.2.17", "verified_at": Self.latchedAt]]
        for state in [foreign, "disabled", serving] as [Any] {
            let exit = try exit { $0["state"] = state }
            #expect(!exit.latches.isEmpty)
            #expect(exit.violationLatchedAt == nil, "\(state)")
        }
    }

    /// Only a latch that carries the state's violation, evidence included,
    /// dates it: neither a latch of another kind nor one of the same kind
    /// with other evidence does.
    @Test func aLatchOfAnotherViolationDoesNotDateTheStates() throws {
        let otherKind: [String: Any] = ["outside_carrier_prefixes": ["ip": "203.0.113.9"]]
        let otherEvidence: [String: Any] = [
            "egress_mismatch": ["d1": "192.0.2.17", "d2": "192.0.2.17", "observed": "198.51.100.4"]
        ]
        for violation in [otherKind, otherEvidence] {
            let exit = try exit { section in
                section["latches"] = [try latch(of: section, at: Self.latchedAt, violation: violation)]
            }
            #expect(exit.latches.count == 1)
            #expect(exit.violationLatchedAt == nil, "\(violation)")
        }
    }

    /// Of several latches, the earliest that carries the state's violation
    /// dates it, wherever it stands in the list; an earlier latch of
    /// another violation does not.
    @Test func theEarliestLatchThatCarriesItIsRead() throws {
        let exit = try exit { section in
            section["latches"] = [
                try latch(
                    of: section, at: Self.latchedAt - 500,
                    violation: ["egress_equals_uplink": ["ip": "198.51.100.4"]]),
                try latch(of: section, at: Self.latchedAt + 300),
                try latch(of: section, at: Self.latchedAt),
                try latch(of: section, at: Self.latchedAt + 100),
            ]
        }
        #expect(exit.latches.count == 4)
        #expect(exit.violationLatchedAt?.seconds == Self.latchedAt)
    }

    @Test func aViolationNoLatchCarriesHasNoLatchedTime() throws {
        let exit = try exit { $0["latches"] = [Any]() }
        guard case .down(.violation) = exit.state else {
            Issue.record("not down for a violation: \(exit.state)")
            return
        }
        #expect(exit.violationLatchedAt == nil)
    }

    /// The exit is down for the violation its one latch carries: no latch
    /// is left for the overview to name beside the state.
    @Test func theLatchTheStateShowsIsNotBehindIt() throws {
        #expect(try exit().latchesBehindTheState.isEmpty)
    }

    /// Preflight finds a foreign network, a disabled exit and a sleeping
    /// Mac before it looks at a latch, so the state says nothing of the
    /// latch that will keep the exit down once that reason is gone.
    @Test func aLatchStandsBehindEveryStateThatIsNoViolation() throws {
        let foreign: [String: Any] = [
            "down": [
                "reason": [
                    "foreign_network_attached": ["findings": [["routable_ipv4": ["interface": "en0"]]]]
                ]
            ]
        ]
        let latched = try exit().latches
        #expect(latched.count == 1)
        for state in [foreign, "disabled", "paused"] as [Any] {
            let exit = try exit { $0["state"] = state }
            #expect(exit.latchesBehindTheState == latched, "\(state)")
        }
    }

    /// Down for one violation with three more latches: the ones that do
    /// not carry the state's violation stand behind it, in the list's
    /// order, the one of the same kind with other evidence among them.
    @Test func theOtherLatchesStandBehindAViolation() throws {
        let uplink: [String: Any] = ["egress_equals_uplink": ["ip": "198.51.100.4"]]
        let otherEvidence: [String: Any] = [
            "egress_mismatch": ["d1": "192.0.2.17", "d2": "192.0.2.17", "observed": "198.51.100.4"]
        ]
        let exit = try exit { section in
            section["latches"] = [
                try latch(of: section, at: Self.latchedAt + 40, violation: uplink),
                try latch(of: section, at: Self.latchedAt),
                try latch(of: section, at: Self.latchedAt - 40, violation: otherEvidence),
                try latch(of: section, at: Self.latchedAt + 10),
            ]
        }
        #expect(exit.latchesBehindTheState.map(\.at.seconds) == [Self.latchedAt + 40, Self.latchedAt - 40])
        #expect(exit.latchesBehindTheState.map(\.violation.kind) == [.egressEqualsUplink, .egressMismatch])
    }

    @Test func noLatchStandsBehindAnyStateWithoutLatches() throws {
        for state in ["disabled", "paused"] as [Any] {
            let exit = try exit {
                $0["state"] = state
                $0["latches"] = [Any]()
            }
            #expect(exit.latchesBehindTheState.isEmpty, "\(state)")
        }
    }
}
