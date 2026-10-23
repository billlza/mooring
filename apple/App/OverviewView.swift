// SPDX-License-Identifier: GPL-3.0-or-later

// The overview (design §15.3): the exit's state, each node's gate and
// verdicts, the SIM gauge, the router and the open alerts at a glance.
// Before `exit init` the exit has no deployment to report, which is said as
// such, never drawn as zeros.

import MooringKit
import SwiftUI

struct OverviewView: View {
    let model: ConsoleModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                exitCard
                if let deployed = model.status?.deployed {
                    if !deployed.alerts.isEmpty {
                        AlertsCard(alerts: deployed.alerts)
                    }
                    NodesCard(status: deployed)
                    GroupBox {
                        SimGauge(sim: deployed.sim)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } label: {
                        Label("SIM", systemImage: "simcard")
                    }
                }
                routerCard
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var exitCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                switch model.status {
                case .noDeployment?:
                    Text("No deployment on this Mac yet")
                        .font(.title3.weight(.semibold))
                    Text(
                        "The exit, its nodes, users and SIM meter appear once `mooringctl exit init` has created a deployment. Until then the daemon reads the M7 only."
                    )
                    .foregroundStyle(.secondary)
                case .deployed(let deployed)?:
                    Label(deployed.exit.state.headline, systemImage: deployed.exit.state.symbol)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(deployed.exit.state.tint)
                    ForEach(deployed.exit.state.details, id: \.self) { detail in
                        Text(detail)
                    }
                    Text("Since \(deployed.exit.since.text).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                case nil:
                    Text("No status from the daemon yet")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Exit", systemImage: "arrow.up.right.circle")
        }
    }

    private var routerCard: some View {
        GroupBox {
            switch model.status?.router {
            case nil:
                Text("No poll of the M7 has been reported yet.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            case .unavailable(let reason, let lastPolledAt)?:
                VStack(alignment: .leading, spacing: 6) {
                    Label(reason.title, systemImage: "antenna.radiowaves.left.and.right.slash")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.orange)
                    Text(reason.advice)
                        .foregroundStyle(.secondary)
                    if let lastPolledAt {
                        Text("Last read \(lastPolledAt.date.formatted(date: .abbreviated, time: .standard)).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            case .available(let polledAt, let status)?:
                RouterGlance(
                    polledAt: polledAt, status: status, advisories: model.status?.advisories ?? [])
            }
        } label: {
            Label("M7 router", systemImage: "antenna.radiowaves.left.and.right")
        }
    }
}

/// The router's main figures: network, band and service, the two signal
/// readings that matter for placement, temperature, battery and traffic.
struct RouterGlance: View {
    let polledAt: UnixTime
    let status: RouterStatus
    /// The settings the exit needs off that are on, as the daemon says.
    let advisories: [RouterAdvisory]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch status.radio {
            case .noService:
                Text("No service")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.orange)
            case .attached(let radio):
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(radio.network)
                        .font(.title2.weight(.semibold))
                    Text("\(radio.band.text) · \(radio.dataService.wire)")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 24) {
                    SignalGauge(label: "RSRP", tenths: radio.lte.rsrp, unit: "dBm", quality: SignalQuality.rsrp)
                    SignalGauge(label: "SINR", tenths: radio.lte.sinr, unit: "dB", quality: SignalQuality.sinr)
                    if radio.nr.rsrp != nil || radio.nr.sinr != nil {
                        SignalGauge(label: "NR RSRP", tenths: radio.nr.rsrp, unit: "dBm", quality: SignalQuality.rsrp)
                        SignalGauge(label: "NR SINR", tenths: radio.nr.sinr, unit: "dB", quality: SignalQuality.sinr)
                    }
                }
            }
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                GridRow {
                    Text("Temperature").foregroundStyle(.secondary)
                    Text("\(status.temperatureC) °C, \(status.thermal.wire)")
                }
                GridRow {
                    Text("Battery").foregroundStyle(.secondary)
                    Text(
                        "\(status.power.battery.charge) %\(status.power.battery.charging ? String(localized: ", charging") : "")"
                    )
                }
                GridRow {
                    Text("Traffic").foregroundStyle(.secondary)
                    Text(
                        "↓ \(Readings.bytes(status.counters.rxBytes))  ↑ \(Readings.bytes(status.counters.txBytes))"
                    )
                }
                GridRow {
                    Text("Polled").foregroundStyle(.secondary)
                    Text(polledAt.date.formatted(date: .omitted, time: .standard))
                }
            }
            if !advisories.isEmpty {
                Label(
                    "On: \(advisories.names); the exit needs these off.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .foregroundStyle(.orange)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// One signal reading, large, with its rule-of-thumb quality.
struct SignalGauge: View {
    let label: String
    let tenths: Int16?
    let unit: String
    let quality: (Int16) -> SignalQuality

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            if let tenths {
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text(Readings.tenths(tenths))
                        .font(.system(size: 28, weight: .semibold, design: .rounded))
                        .monospacedDigit()
                    Text(unit)
                        .foregroundStyle(.secondary)
                }
                Text(quality(tenths).title)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(quality(tenths).color)
            } else {
                Text("not reported")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// The open alerts, most severe first, as the daemon raised them.
struct AlertsCard: View {
    let alerts: [OpenAlert]

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(sorted.enumerated()), id: \.offset) { _, alert in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: alert.severity == .critical ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(alert.severity.tint)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(alert.condition.text)
                            Text("\(alert.severity.text) · since \(alert.activeSince.text)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Open alerts", systemImage: "bell.badge")
        }
    }

    /// Critical alerts first; otherwise in the daemon's order.
    private var sorted: [OpenAlert] {
        alerts.filter { $0.severity == .critical } + alerts.filter { $0.severity == .warning }
    }
}

/// Each node's gate and latest in-chain verdicts.
struct NodesCard: View {
    let status: DeployedStatus

    var body: some View {
        GroupBox {
            if status.nodes.isEmpty {
                Text("No nodes yet.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    ForEach(status.sortedNodes, id: \.id) { node in
                        GridRow {
                            Text(verbatim: node.id.text)
                                .font(.body.weight(.semibold))
                            Text(gate(node.row))
                                .foregroundStyle(.secondary)
                            verdict("REALITY", node.row.verdicts.reality)
                            verdict("Hysteria2", node.row.verdicts.hy2)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } label: {
            Label("Nodes", systemImage: "server.rack")
        }
    }

    private func gate(_ row: NodeRow) -> String {
        switch row.agent {
        case .reported(let report): String(localized: "gate \(report.gate.text)")
        case .unreachable(_, let cause): String(localized: "unreachable: \(cause.text)")
        case .notPolled: String(localized: "not polled yet")
        }
    }

    private func verdict(_ name: String, _ result: InChainResult?) -> some View {
        HStack(spacing: 4) {
            Circle()
                .fill(result?.outcome.tint ?? .secondary)
                .frame(width: 8, height: 8)
            Text(verbatim: name)
            Text(result?.outcome.text ?? String(localized: "not run yet"))
                .foregroundStyle(.secondary)
        }
    }
}
