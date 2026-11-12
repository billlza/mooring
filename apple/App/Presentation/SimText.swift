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

extension SimNetwork {
    /// The SIM's name, or that it reports none, and the network's codes
    /// as the Router screen writes them. The name is the carrier's text:
    /// every place that shows it passes a `String` to `Text`, which reads
    /// no Markdown.
    var text: String {
        if let spn {
            "\(spn) (\(plmn.mcc)-\(plmn.mnc))"
        } else {
            String(localized: "a SIM without a name (\(plmn.mcc)-\(plmn.mnc))")
        }
    }
}

extension OtherNetwork {
    /// What the M7 reports now, and since when.
    var text: String {
        String(localized: "\(network.text), since \(since.text)")
    }
}

extension SimNetworkChange {
    var headline: String {
        switch difference {
        case .simName: String(localized: "The M7 reports another SIM than the one on record")
        case .networkOnly: String(localized: "The M7 reports another network than the one on record")
        }
    }

    /// What the M7 reports and since when, against what the two records
    /// about the SIM go with.
    var detail: String {
        switch difference {
        case .simName:
            String(
                localized:
                    "Since \(since.text) the M7 reports \(reported.text). The carrier check and the billing cycle on record go with \(recorded.text)."
            )
        case .networkOnly:
            String(
                localized:
                    "Since \(since.text) the M7 reports \(reported.text). The carrier check and the billing cycle on record go with \(recorded.text): either the SIM was changed for another of the same name, or its carrier moved it to another network."
            )
        }
    }

    /// What to do after a SIM change (`docs/runbooks/swap-day.md`, section
    /// 2, steps 3 to 6), and what ends the notice.
    var remedy: String {
        String(
            localized:
                "If the SIM was changed, both records are the old SIM's. Record them for the new one: `docs/runbooks/swap-day.md`, section 2, steps 3 to 6 (`mooringctl exit disable`, `exit observe`, `exit record-carrier --replace`, `sim set-anchor`, `node apply` for each node, `exit enable`). This notice ends once either is recorded with other values, or once the M7 reports \(recorded.text) again."
        )
    }
}

extension BaselineOrigin {
    /// What the network on record is, and what the comparison cannot see.
    var note: String {
        switch self {
        case .recorded:
            String(
                localized:
                    "On record is what the M7 reported at the first poll that found it attached after the carrier check or the billing cycle was last recorded; the daemon compares every later poll with it. The daemon reads the SIM's name and the network's codes only, so two SIMs of one carrier look alike."
            )
        case .noRecord:
            String(
                localized:
                    "The daemon had no record of the SIM's network when it began this one, so on record is what the M7 reported at the first poll after that, which may not be what it reported when the carrier check and the billing cycle were recorded: a SIM changed before that is not noticed. The daemon reads the SIM's name and the network's codes only, so two SIMs of one carrier look alike."
            )
        case .recordUnreadable:
            String(
                localized:
                    "The daemon could not read its record of the SIM's network and began it again, so on record is what the M7 reported at the first poll after that, which may not be what it reported when the carrier check and the billing cycle were recorded: a SIM changed before that is not noticed. The daemon reads the SIM's name and the network's codes only, so two SIMs of one carrier look alike."
            )
        }
    }
}
