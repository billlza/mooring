// SPDX-License-Identifier: GPL-3.0-or-later

// The capacity screen (design §15.3): the egress rates now, the uplink's
// use against its measured baseline, the loaded latency and whether the
// line is saturated.

import MooringKit
import SwiftUI

struct CapacityView: View {
    let status: DeployedStatus

    var body: some View {
        if let capacity = status.capacity {
            Form {
                Section("Now") {
                    LabeledContent("Sending", value: rate(capacity.txBps))
                    LabeledContent("Receiving", value: rate(capacity.rxBps))
                    LabeledContent("Uplink use", value: capacity.uplinkUse.text)
                    LabeledContent(
                        "Loaded latency",
                        value: capacity.rttInflationMs.map { String(localized: "+\($0) ms over idle") }
                            ?? String(localized: "the probe failed"))
                    LabeledContent("Saturation") {
                        Text(capacity.saturation.text)
                            .foregroundStyle(capacity.saturation.tint)
                    }
                    LabeledContent("Sampled", value: capacity.at.text)
                }
                Section {
                } footer: {
                    Text(
                        "With the default thresholds, saturated means uplink use of at least \(85) %, or latency inflated by \(200) ms or more, for \(10) minutes; every user shares the uplink."
                    )
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView(
                "No capacity sample yet",
                systemImage: "speedometer",
                description: Text("The daemon samples the egress once the exit runs.")
            )
        }
    }
}
