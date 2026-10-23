// SPDX-License-Identifier: GPL-3.0-or-later

// The uplink's capacity in a deployment's status (`mooring-daemon-core`'s
// `capacity::CapacityStatus`, design §15.3): the egress rates now, the
// uplink's use against its measured baseline, the loaded latency and
// whether the line is saturated.

import Foundation

/// The uplink's use, against the recorded baseline's median.
public enum UplinkUse: Decodable, Hashable, Sendable {
    /// No uplink baseline is recorded yet.
    case noBaseline
    /// The send rate in thousandths of the baseline's p50.
    case measured(permille: UInt64, baselineP50Bps: UInt64)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("no_baseline", nil): self = .noBaseline
        case ("measured", let value?):
            let object = try value.fields("permille", "baseline_p50_bps")
            self = .measured(
                permille: try object.field(UInt64.self, "permille"),
                baselineP50Bps: try object.field(UInt64.self, "baseline_p50_bps"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// Whether the uplink is saturated: use or latency over their thresholds,
/// held long enough.
public enum Saturation: Decodable, Hashable, Sendable {
    case noEvidence
    case clear
    case building(since: UnixTime)
    case saturated(since: UnixTime)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("no_evidence", nil): self = .noEvidence
        case ("clear", nil): self = .clear
        case ("building", let value?):
            self = .building(since: try value.fields("since").field(UnixTime.self, "since"))
        case ("saturated", let value?):
            self = .saturated(since: try value.fields("since").field(UnixTime.self, "since"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// The latest capacity view.
public struct CapacityStatus: Decodable, Hashable, Sendable {
    public let at: UnixTime
    /// The egress transmit rate, in bit/s.
    public let txBps: UInt64
    /// The egress receive rate, in bit/s.
    public let rxBps: UInt64
    public let uplinkUse: UplinkUse
    /// The round-trip inflation in milliseconds; `nil` when the probe
    /// failed.
    public let rttInflationMs: UInt64?
    public let saturation: Saturation

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at
        case txBps = "tx_bps"
        case rxBps = "rx_bps"
        case uplinkUse = "uplink_use"
        case rttInflationMs = "rtt_inflation_ms"
        case saturation
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        txBps = try object.decode(UInt64.self, forKey: .txBps)
        rxBps = try object.decode(UInt64.self, forKey: .rxBps)
        uplinkUse = try object.decode(UplinkUse.self, forKey: .uplinkUse)
        rttInflationMs = try object.decodeNullable(UInt64.self, forKey: .rttInflationMs)
        saturation = try object.decode(Saturation.self, forKey: .saturation)
    }
}
