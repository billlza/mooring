// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension UnixTime {
    /// The day and time, in the user's calendar and time zone.
    var text: String {
        date.formatted(date: .abbreviated, time: .standard)
    }
}

extension CalendarDate {
    /// The UTC day as the daemon wrote it, `YYYY-MM-DD`.
    var display: String { text }
}

/// Bytes as the console spells them.
func bytes(_ count: UInt64) -> String {
    Readings.bytes(count)
}

/// A rate in bit/s, in decimal units.
func rate(_ bitsPerSecond: UInt64) -> String {
    let megabits = Double(bitsPerSecond) / 1_000_000
    return megabits.formatted(.number.precision(.fractionLength(1))) + " Mbit/s"
}

/// A span in seconds, as `mooringctl` spells it.
func span(_ seconds: UInt64) -> String {
    let (days, clock) = Readings.span(seconds)
    return String(localized: "\(days) d \(clock)")
}
