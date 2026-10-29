// SPDX-License-Identifier: GPL-3.0-or-later

// The signal over the last 24 hours (design §15.6 rule 11): one chart of
// RSRP and one of SINR (their units differ), each with an LTE line and,
// when the M7 reported one, an NR line, drawn from the samples the daemon
// recorded. A reading the M7 did not report, a poll without service and a
// failed poll break the line rather than bridge the gap; the events are
// marked as vertical rules.

import Charts
import MooringKit
import SwiftUI

/// One reading on a chart: its time, its value in the chart's unit, and
/// the line it belongs to (a radio's contiguous run of readings).
struct SignalPoint: Identifiable {
    let id: Int
    let time: Date
    let value: Double
    let radio: String
    let run: Int

    /// The line's name: the radio and its run, so a gap breaks the line.
    var line: String { "\(radio) \(run)" }
}

/// Which reading a chart shows.
enum SignalMetric {
    case rsrp
    case sinr

    var unit: String {
        switch self {
        case .rsrp: "dBm"
        case .sinr: "dB"
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .rsrp: "RSRP"
        case .sinr: "SINR"
        }
    }

    func lte(_ radio: SampledAttachment) -> Int16? {
        switch self {
        case .rsrp: radio.lte.rsrp
        case .sinr: radio.lte.sinr
        }
    }

    func nr(_ radio: SampledAttachment) -> Int16? {
        switch self {
        case .rsrp: radio.nr.rsrp
        case .sinr: radio.nr.sinr
        }
    }

    /// The points of `samples` for one radio, in runs that a gap ends.
    func points(_ samples: [RadioSample], radio name: String, reading: (SampledAttachment) -> Int16?) -> [SignalPoint] {
        var points: [SignalPoint] = []
        var run = 0
        var inRun = false
        for sample in samples {
            guard let radio = sample.attachment, let tenths = reading(radio) else {
                if inRun {
                    run += 1
                    inRun = false
                }
                continue
            }
            inRun = true
            points.append(
                SignalPoint(id: points.count, time: sample.at.date, value: Double(tenths) / 10, radio: name, run: run))
        }
        return points
    }

    /// The LTE points, then the NR points when the M7 reported any.
    func points(_ samples: [RadioSample]) -> [SignalPoint] {
        var points = self.points(samples, radio: "LTE", reading: lte)
        let nr = self.points(samples, radio: "NR", reading: self.nr)
        for point in nr {
            points.append(
                SignalPoint(id: points.count, time: point.time, value: point.value, radio: point.radio, run: point.run))
        }
        return points
    }
}

struct SignalHistoryChart: View {
    let samples: [RadioSample]
    let events: [RadioEvent]
    /// The window's end: the chart shows the 24 hours before it.
    let end: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            chart(.rsrp)
            chart(.sinr)
        }
    }

    private func chart(_ metric: SignalMetric) -> some View {
        // Plain strings, so the axis and series names are not localizable
        // keys (the catalog check would want translations).
        let timeLabel: String = "Time"
        let lineLabel: String = "Line"
        let radioLabel: String = "Radio"
        let eventLabel: String = "Event"
        let unit: String = metric.unit
        return VStack(alignment: .leading, spacing: 4) {
            Text(metric.title)
                .font(.caption.weight(.semibold))
            Chart {
                ForEach(metric.points(samples)) { point in
                    LineMark(
                        x: .value(timeLabel, point.time),
                        y: .value(unit, point.value),
                        series: .value(lineLabel, point.line)
                    )
                    .foregroundStyle(by: .value(radioLabel, point.radio))
                    .interpolationMethod(.linear)
                }
                ForEach(Array(events.enumerated()), id: \.offset) { _, event in
                    RuleMark(x: .value(eventLabel, event.at.date))
                        .foregroundStyle(.orange.opacity(0.4))
                }
            }
            .chartXScale(domain: end.addingTimeInterval(-86_400)...end)
            .chartYAxisLabel(unit)
            .frame(height: 140)
        }
    }
}
