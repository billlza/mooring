// SPDX-License-Identifier: GPL-3.0-or-later

// A deployment's status (`mooring-daemon-core`'s `MacStatusV1`, design
// §15.2): the `deployed` document of the console. It carries the exit,
// the SIM meter, the router panel with the settings the exit needs off,
// the capacity, one row per user and per node, and the open alerts. Users
// appear by opaque id and public alias only.

import Foundation

/// A deployment's status.
public struct DeployedStatus: Decodable, Hashable, Sendable {
    /// The version this build reads.
    public static let version: UInt32 = 1

    public let at: UnixTime
    public let exit: ExitSection
    public let sim: SimMeterStatus
    public let router: RouterReading
    /// The settings the exit needs off that the router panel shows on, as
    /// the daemon decides them.
    public let advisories: [RouterAdvisory]
    /// The latest capacity view; `nil` before the first sample.
    public let capacity: CapacityStatus?
    public let usage: UsageView
    public let users: [UserId: UserRow]
    /// Every node, retired ones included.
    public let nodes: [NodeId: NodeRow]
    /// The open alerts, in the daemon's key order.
    public let alerts: [OpenAlert]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, at, exit, sim, router, advisories, capacity, usage, users, nodes, alerts
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        let version = try object.decode(UInt32.self, forKey: .version)
        guard version == Self.version else {
            throw ConsoleDecodingError.unsupportedVersion(version)
        }
        at = try object.decode(UnixTime.self, forKey: .at)
        exit = try object.decode(ExitSection.self, forKey: .exit)
        sim = try object.decode(SimMeterStatus.self, forKey: .sim)
        router = try object.decode(RouterReading.self, forKey: .router)
        advisories = try object.decode([RouterAdvisory].self, forKey: .advisories)
        capacity = try object.decodeNullable(CapacityStatus.self, forKey: .capacity)
        usage = try object.decode(UsageView.self, forKey: .usage)
        users = try object.decode([UserId: UserRow].self, forKey: .users)
        nodes = try object.decode([NodeId: NodeRow].self, forKey: .nodes)
        alerts = try object.decode([OpenAlert].self, forKey: .alerts)
    }

    /// The node rows in the order of their ids.
    public var sortedNodes: [(id: NodeId, row: NodeRow)] {
        nodes.sorted { $0.key < $1.key }.map { (id: $0.key, row: $0.value) }
    }

    /// The user rows in the order of their ids.
    public var sortedUsers: [(id: UserId, row: UserRow)] {
        users.sorted { $0.key < $1.key }.map { (id: $0.key, row: $0.value) }
    }
}
