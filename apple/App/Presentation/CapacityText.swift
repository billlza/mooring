// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension UplinkUse {
    var text: String {
        switch self {
        case .noBaseline: String(localized: "no uplink baseline recorded")
        case .measured(let permille, let baseline):
            String(
                localized:
                    "\((Double(permille) / 10).formatted(.number.precision(.fractionLength(1)))) % of the baseline's median, \(rate(baseline))"
            )
        }
    }
}

extension Saturation {
    var text: String {
        switch self {
        case .noEvidence: String(localized: "no evidence yet")
        case .clear: String(localized: "clear")
        case .building(let since): String(localized: "building since \(since.text)")
        case .saturated(let since): String(localized: "saturated since \(since.text)")
        }
    }

    var tint: Color {
        switch self {
        case .noEvidence, .clear: .secondary
        case .building: .orange
        case .saturated: .red
        }
    }
}
