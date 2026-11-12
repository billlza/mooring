// SPDX-License-Identifier: GPL-3.0-or-later

// The SIM screen (design §15.3): the billing cycle, the line's bytes
// received and sent against the warning, the stop policy and the plan's
// line, whether the meter is exact, the forecast with each threshold's
// crossing, and the SIM and network on record against what the M7 reports
// now, with a notice when they differ.

import MooringKit
import SwiftUI

struct SimView: View {
    let status: DeployedStatus

    var body: some View {
        let sim = status.sim
        Form {
            Section {
                if let change = sim.network.change {
                    SimNetworkNotice(change: change)
                }
                SimGauge(sim: sim)
                    .padding(.vertical, 4)
            }
            Section {
                if let baseline = sim.network.baseline {
                    LabeledContent("On record", value: baseline.network.text)
                    LabeledContent("First reported", value: baseline.firstSeen.text)
                    LabeledContent("Reported now") {
                        if let other = baseline.other {
                            Text(other.text)
                                .foregroundStyle(.orange)
                        } else {
                            Text("the same")
                        }
                    }
                } else {
                    Text("No poll has found the M7 attached since the record began: there is nothing to compare yet.")
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("SIM and network")
            } footer: {
                Text(sim.network.origin.note)
            }
            Section("Cycle") {
                LabeledContent("Started", value: sim.cycle.start.display)
                LabeledContent("Next cycle", value: sim.cycle.nextStart.display)
                LabeledContent("Received", value: bytes(sim.rxBytes))
                LabeledContent("Sent", value: bytes(sim.txBytes))
                LabeledContent("Accuracy") {
                    Text(sim.accuracy.text)
                        .foregroundStyle(sim.accuracy == .exact ? Color.primary : Color.orange)
                }
            }
            Section {
                LabeledContent("Warning at", value: bytes(sim.thresholds.warnBytes))
                LabeledContent("Stop", value: sim.thresholds.stop.text)
                if let line = sim.thresholds.planLine {
                    LabeledContent(line.kind.text, value: bytes(line.bytes))
                } else {
                    LabeledContent("Plan's line", value: String(localized: "none"))
                }
            } header: {
                Text("Thresholds")
            } footer: {
                Text("`mooringctl sim set-plan`, `set-stop` and `set-anchor` change them from Terminal.")
            }
            Section("Forecast") {
                switch sim.forecast {
                case .projected(let forecast):
                    LabeledContent("Used this cycle", value: bytes(forecast.usedBytes))
                    LabeledContent("Daily average", value: bytes(forecast.dailyAverageBytes))
                    LabeledContent("Projected for the cycle", value: bytes(forecast.projectedBytes))
                    ForEach(forecast.crossings, id: \.self) { crossing in
                        LabeledContent("\(crossing.threshold.text) (\(bytes(crossing.bytes)))") {
                            Text(crossing.crossing.text)
                                .foregroundStyle(crossing.crossing.tint)
                        }
                    }
                    LabeledContent("As of", value: forecast.asOf.text)
                case .unavailable(let reason):
                    Text("No forecast: \(reason.text).")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
    }
}

/// The notice that the M7 reports another SIM or network than the carrier
/// check and the billing cycle on record go with, and what to do. The
/// overview, the SIM screen and the Exit screen show the same one.
struct SimNetworkNotice: View {
    let change: SimNetworkChange

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(change.headline, systemImage: "exclamationmark.triangle.fill")
                .font(.body.weight(.semibold))
                .foregroundStyle(.orange)
            Text(change.detail)
            Text(change.remedy)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The cycle's bytes against the warning and the stop, as a bar.
struct SimGauge: View {
    let sim: SimMeterStatus

    var body: some View {
        let used = Self.used(sim)
        let limit = Self.limit(sim.thresholds)
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(used.map(bytes) ?? String(localized: "unknown"))
                    .font(.title2.weight(.semibold))
                    .monospacedDigit()
                Text("of \(bytes(limit)) this cycle")
                    .foregroundStyle(.secondary)
            }
            if let used {
                ProgressView(value: Double(min(used, limit)), total: Double(max(limit, 1)))
                    .tint(used >= sim.thresholds.warnBytes ? .orange : .accentColor)
            }
            Text("Warning at \(bytes(sim.thresholds.warnBytes)).")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(
                "This cycle began on \(sim.cycle.start.display); the next begins on \(sim.cycle.nextStart.display) (UTC). The meter counts this Mac's traffic through the M7, whichever SIM is in it. After a SIM change, or when the plan starts on another day, move the cycle with `mooringctl sim set-anchor`."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    /// The bytes used this cycle: the forecast's, which the daemon checked
    /// for overflow, or the meter's two counts when they add up.
    static func used(_ sim: SimMeterStatus) -> UInt64? {
        if case .projected(let forecast) = sim.forecast {
            return forecast.usedBytes
        }
        let (sum, overflow) = sim.rxBytes.addingReportingOverflow(sim.txBytes)
        return overflow ? nil : sum
    }

    /// The bar's end: the hard stop, or the plan's line, or the warning.
    static func limit(_ thresholds: SimThresholds) -> UInt64 {
        switch (thresholds.stop, thresholds.planLine) {
        case (.hardStop(let stop), _): stop
        case (.acceptDeprioritisation, let line?): line.bytes
        case (.acceptDeprioritisation, nil): thresholds.warnBytes
        }
    }
}
