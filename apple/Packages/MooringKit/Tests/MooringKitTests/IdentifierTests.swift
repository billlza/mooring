// SPDX-License-Identifier: GPL-3.0-or-later

// The names a status uses for nodes, users and days: the mirror orders node
// and user ids by their bytes, as the Rust maps do, so the console lists
// rows in the order `mooringctl` prints them; days order as dates do; an id
// is a map key in either direction; and the key type never stands for an
// integer (an array index).

import Foundation
import Testing

@testable import MooringKit

@Suite struct IdentifierTests {
    /// Byte order, which neither natural order ("a9" before "a10") nor
    /// case-blind order ("a" before "Z") gives.
    private static let unordered = ["b", "a9", "Z", "a10", "a"]
    private static let byteOrder = ["Z", "a", "a10", "a9", "b"]

    @Test func nodeIdsOrderByTheirBytes() {
        #expect(Self.unordered.map(NodeId.init).sorted().map(\.text) == Self.byteOrder)
    }

    @Test func userIdsOrderByTheirBytes() {
        #expect(Self.unordered.map(UserId.init).sorted().map(\.text) == Self.byteOrder)
    }

    @Test func daysOrderAsDates() {
        let days = ["2026-11-01", "2025-12-31", "2026-10-31"].map(CalendarDate.init)
        #expect(days.sorted().map(\.text) == ["2025-12-31", "2026-10-31", "2026-11-01"])
    }

    @Test func idsAreReadFromAStringAndAsMapKeys() throws {
        let decoder = JSONDecoder()
        #expect(try decoder.decode(UserId.self, from: Data(#""fxuseraaab""#.utf8)).text == "fxuseraaab")
        #expect(try decoder.decode(NodeId.self, from: Data(#""lon1""#.utf8)).text == "lon1")
        let byUser = try decoder.decode([UserId: Int].self, from: Data(#"{"u2": 2, "u1": 1}"#.utf8))
        #expect(byUser == [UserId("u1"): 1, UserId("u2"): 2])
        let byNode = try decoder.decode([NodeId: Int].self, from: Data(#"{"lon1": 1}"#.utf8))
        #expect(byNode == [NodeId("lon1"): 1])
    }

    @Test func anIdIsItsOwnMapKey() {
        #expect(UserId("u1").codingKey.stringValue == "u1")
        #expect(NodeId("lon1").codingKey.stringValue == "lon1")
        #expect(UserId(codingKey: AnyKey("u1")) == UserId("u1"))
        #expect(NodeId(codingKey: AnyKey("lon1")) == NodeId("lon1"))
    }

    @Test func theKeyTypeNeverStandsForAnIndex() {
        #expect(AnyKey(intValue: 0) == nil)
        #expect(AnyKey("x").intValue == nil)
        #expect(AnyKey(stringValue: "x")?.stringValue == "x")
    }

    /// The serving scenario with eight nodes and eight users, ids the Rust
    /// types allow whose byte order is not their natural order, and rows
    /// that all differ: the console lists the rows in byte order, each with
    /// its own row. The maps hold their entries in an order of their own,
    /// which matches the sorted one by chance once in 8! lists.
    @Test func theRowsAreListedInByteOrder() throws {
        var json = try Fixtures.json(try Fixtures.data("contract/status-fixtures/serving.json"))
        let document = try #require(json as? [String: Any])
        let node = try #require((document["nodes"] as? [String: Any])?["lon1"] as? [String: Any])
        let user = try #require((document["users"] as? [String: Any])?["fxuseraaab"] as? [String: Any])
        let activity = try #require(user["activity"] as? [String: Any])
        json = try JSONPaths.editing(json, at: ["nodes"]) { nodes in
            for (offset, id) in ["lon10", "par1", "lon9", "ab2", "fra1", "lon2"].enumerated() {
                var copy = node
                copy["current_generation"] = 10 + offset
                nodes[id] = copy
            }
        }
        json = try JSONPaths.editing(json, at: ["users"]) { users in
            for (offset, id) in ["fxusera7aa", "fxuserzzzz", "fxusera22a", "fxuser2222", "fxuserm3m3"].enumerated() {
                var seen = activity
                seen["last_seen"] = 1_791_450_000 + offset
                var copy = user
                copy["activity"] = seen
                users[id] = copy
            }
        }
        let status = try JSONDecoder().decode(DeployedStatus.self, from: try Fixtures.encode(json))
        #expect(
            status.sortedNodes.map(\.id.text) == [
                "ab2", "ams1", "fra1", "lon1", "lon10", "lon2", "lon9", "par1",
            ])
        #expect(
            status.sortedUsers.map(\.id.text) == [
                "fxuser2222", "fxusera22a", "fxusera7aa", "fxuseraaab", "fxuseraaac", "fxuseraaad",
                "fxuserm3m3", "fxuserzzzz",
            ])
        #expect(Set(status.nodes.values).count == 8 && Set(status.users.values).count == 8)
        #expect(status.sortedNodes.allSatisfy { status.nodes[$0.id] == $0.row })
        #expect(status.sortedUsers.allSatisfy { status.users[$0.id] == $0.row })
    }
}
