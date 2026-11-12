// SPDX-License-Identifier: GPL-3.0-or-later

// The SIM's network (`mooring-daemon-core`'s `sim_network`, design §10.2,
// §15.2): the baseline, which is what the M7 reported at the first poll
// under the carrier check and the billing cycle now recorded, or the
// network the operator had the daemon take since (`mooringctl sim
// accept-network`); and the other network the M7 reports now, if it does.
// The carrier check and the cycle are records about one SIM; another
// network than the baseline's is how the console learns that they may be
// another SIM's.

import Foundation

/// What the M7 reports that tells one SIM from another: the SIM's name and
/// the codes of the network it is registered on. It names a carrier and a
/// network, never a subscriber.
public struct SimNetwork: Decodable, Hashable, Sendable {
    /// The SIM's service provider name; `nil` for a SIM that carries none.
    public let spn: String?
    public let plmn: Plmn

    enum CodingKeys: String, CodingKey, CaseIterable {
        case spn, plmn
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        spn = try object.decodeNullable(String.self, forKey: .spn)
        plmn = try object.decode(Plmn.self, forKey: .plmn)
    }
}

/// How the baseline came to be taken when it was.
public enum BaselineOrigin: String, Decodable, Sendable, CaseIterable {
    /// The daemon found no record when it started: a SIM changed before
    /// then is not noticed.
    case noRecord = "no_record"
    /// The carrier check or the billing cycle was recorded.
    case recorded
    /// The record could not be read and was begun again: a SIM changed
    /// before then is not noticed.
    case recordUnreadable = "record_unreadable"
    /// The operator had the daemon take the network the M7 then reported
    /// (`mooringctl sim accept-network`); the carrier check and the
    /// billing cycle were not recorded again for it.
    case accepted
}

/// A network other than the baseline's, which the M7 reports now.
public struct OtherNetwork: Decodable, Hashable, Sendable {
    public let network: SimNetwork
    /// Since when the M7 has reported a network other than the baseline's.
    public let since: UnixTime

    enum CodingKeys: String, CodingKey, CaseIterable {
        case network, since
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        network = try object.decode(SimNetwork.self, forKey: .network)
        since = try object.decode(UnixTime.self, forKey: .since)
    }
}

/// The baseline, and the other network the M7 reports now, if it does.
public struct NetworkBaseline: Decodable, Hashable, Sendable {
    public let network: SimNetwork
    /// When the baseline was taken, by the Mac's clock: the time of the
    /// poll that gave it, or, for one the operator took (`accepted`), the
    /// time it was taken.
    public let firstSeen: UnixTime
    /// `nil` while the M7 reports the baseline's network; never that
    /// network itself.
    public let other: OtherNetwork?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case network
        case firstSeen = "first_seen"
        case other
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        network = try object.decode(SimNetwork.self, forKey: .network)
        firstSeen = try object.decode(UnixTime.self, forKey: .firstSeen)
        other = try object.decodeNullable(OtherNetwork.self, forKey: .other)
        // The Rust type refuses it too; what a change differs in is then
        // always one of `NetworkDifference`'s cases.
        guard other?.network != network else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath + [CodingKeys.other],
                    debugDescription: "the other network is the baseline's own"))
        }
    }
}

/// What another network differs from the baseline's in.
public enum NetworkDifference: Hashable, Sendable, CaseIterable {
    /// The SIM's name: another SIM, unless a carrier renamed its own.
    case simName
    /// The network's codes alone, under the same name or none: a SIM
    /// changed for one of the same name, or one SIM on another network.
    case networkOnly
}

/// The M7 reports another network than the baseline's.
public struct SimNetworkChange: Hashable, Sendable {
    /// The baseline: what the carrier check and the cycle are taken to go
    /// with.
    public let recorded: SimNetwork
    /// When the baseline was taken.
    public let recordedAt: UnixTime
    /// What the M7 reports now.
    public let reported: SimNetwork
    /// Since when it has reported another network than the baseline's.
    public let since: UnixTime

    public var difference: NetworkDifference {
        recorded.spn == reported.spn ? .networkOnly : .simName
    }
}

/// What the status says of the SIM's network (`sim.network`).
public struct SimNetworkStatus: Decodable, Hashable, Sendable {
    public let origin: BaselineOrigin
    /// `nil` until a poll finds the M7 attached under the carrier check
    /// and the billing cycle now recorded.
    public let baseline: NetworkBaseline?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case origin, baseline
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        origin = try object.decode(BaselineOrigin.self, forKey: .origin)
        baseline = try object.decodeNullable(NetworkBaseline.self, forKey: .baseline)
    }

    /// The change to show: `nil` without a baseline, and while the M7
    /// reports the baseline's network.
    public var change: SimNetworkChange? {
        guard let baseline, let other = baseline.other else {
            return nil
        }
        return SimNetworkChange(
            recorded: baseline.network, recordedAt: baseline.firstSeen, reported: other.network,
            since: other.since)
    }
}
