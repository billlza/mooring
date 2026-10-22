// SPDX-License-Identifier: GPL-3.0-or-later

// How the console writes the M7's numbers: readings from tenths and
// durations as `mooringctl`'s summary spells them, so the app and the CLI
// can be compared, and byte counts in decimal units. Deterministic (no
// locale), so tests pin them; the app words what is not a number (a span's
// day unit, "not reported") in the user's language.

import Foundation

public enum Readings {
    /// A reading in tenths with one decimal only when it has one:
    /// `-1040` is `-104`, `-1045` is `-104.5`, `-5` is `-0.5`.
    public static func tenths(_ value: Int16) -> String {
        let sign = value < 0 ? "-" : ""
        let magnitude = value.magnitude
        let (whole, tenth) = (magnitude / 10, magnitude % 10)
        return tenth == 0 ? "\(sign)\(whole)" : "\(sign)\(whole).\(tenth)"
    }

    /// A reading with its unit.
    public static func reading(_ value: Int16, unit: String) -> String {
        "\(tenths(value)) \(unit)"
    }

    /// A duration in seconds as whole days and the `<hh>:<mm>:<ss>` after
    /// them, which `mooringctl` prints as `<days>d <hh>:<mm>:<ss>`.
    public static func span(_ seconds: UInt64) -> (days: UInt64, clock: String) {
        let rest = seconds % 86_400
        let clock = [rest / 3600, rest % 3600 / 60, rest % 60]
            .map { $0 < 10 ? "0\($0)" : "\($0)" }
            .joined(separator: ":")
        return (seconds / 86_400, clock)
    }

    /// Bytes in decimal units with one decimal above a kilobyte:
    /// `512 B`, `1.5 kB`, `591.7 MB`, `81.0 GB`.
    public static func bytes(_ count: UInt64) -> String {
        let units = ["kB", "MB", "GB", "TB", "PB", "EB"]
        guard count >= 1000 else {
            return "\(count) B"
        }
        var scaled = count
        var unit = 0
        // Tenths of the unit, rounded down: exact integer arithmetic.
        while scaled >= 1_000_000, unit < units.count - 1 {
            scaled /= 1000
            unit += 1
        }
        let tenthsOfUnit = scaled / 100
        return "\(tenthsOfUnit / 10).\(tenthsOfUnit % 10) \(units[unit])"
    }
}

/// A signal reading's place in conventional LTE guidance, used only to
/// colour a reading for antenna placement; it decides nothing. RSRP: -80
/// dBm and above excellent, -90 good, -100 fair, below poor; SINR: 20 dB
/// and above excellent, 13 good, 0 fair, below poor. These are rules of
/// thumb, not 3GPP limits *(inference)*.
public enum SignalQuality: String, Sendable, CaseIterable {
    case excellent, good, fair, poor

    /// RSRP in tenths of dBm.
    public static func rsrp(tenths value: Int16) -> SignalQuality {
        switch value {
        case (-800)...: .excellent
        case (-900)..<(-800): .good
        case (-1000)..<(-900): .fair
        default: .poor
        }
    }

    /// SINR in tenths of dB.
    public static func sinr(tenths value: Int16) -> SignalQuality {
        switch value {
        case 200...: .excellent
        case 130..<200: .good
        case 0..<130: .fair
        default: .poor
        }
    }
}
