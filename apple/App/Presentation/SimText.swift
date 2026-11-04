// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension Pairing {
    var text: String {
        switch self {
        case .paired: String(localized: "paired")
        case .unpaired: String(localized: "unpaired")
        }
    }
}

extension MeterAccuracy {
    var text: String {
        switch self {
        case .exact: String(localized: "Exact")
        case .lowerBound:
            String(localized: "Lower bound: the M7's Wi-Fi or offload is on, or a counter reset was seen")
        }
    }
}

extension StopPolicy {
    var text: String {
        switch self {
        case .hardStop(let stop): String(localized: "Hard stop at \(bytes(stop))")
        case .acceptDeprioritisation:
            String(localized: "Keep serving past the fair-use line, accepting deprioritisation")
        }
    }
}

extension PlanLineKind {
    var text: String {
        switch self {
        case .fairUse: String(localized: "Fair-use line")
        case .allowance: String(localized: "Allowance")
        }
    }
}

extension SimThreshold {
    var text: String {
        switch self {
        case .warn: String(localized: "Warning")
        case .hardStop: String(localized: "Hard stop")
        case .fairUse: String(localized: "Fair-use line")
        case .allowance: String(localized: "Allowance")
        }
    }
}

extension Crossing {
    var text: String {
        switch self {
        case .reached(let on): String(localized: "reached on \(on.display)")
        case .projected(let on): String(localized: "projected for \(on.display)")
        case .notThisCycle: String(localized: "not this cycle")
        }
    }

    var tint: Color {
        switch self {
        case .reached: .red
        case .projected: .orange
        case .notThisCycle: .secondary
        }
    }
}

extension ForecastErrorKind {
    var text: String {
        switch self {
        case .noBins: String(localized: "no metered day yet: there is nothing to project from")
        case .nothingElapsed: String(localized: "no time has passed in the billing cycle")
        case .binOutsideCycle: String(localized: "a metered day lies outside the cycle's elapsed days")
        case .binsOutOfOrder: String(localized: "a metered day repeats or precedes an earlier one")
        case .missingDay: String(localized: "a metered day is missing")
        case .counterOverflow: String(localized: "the SIM byte counts overflow a 64-bit counter")
        case .model: String(localized: "the plan's figures are inconsistent")
        }
    }
}
