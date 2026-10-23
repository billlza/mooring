// SPDX-License-Identifier: GPL-3.0-or-later

// The nodes screen (design §15.3): per node, its role and stage, its
// generation against the deployment's, the latest in-chain verdict per
// protocol, and its agent's report (gate, holds, halt, handshake and watch
// ages, conditions, engines, host health and this month's transfer), or
// why it could not be polled.

import MooringKit
import SwiftUI

struct NodesView: View {
    let status: DeployedStatus

    var body: some View {
        if status.nodes.isEmpty {
            ContentUnavailableView(
                "No nodes",
                systemImage: "server.rack",
                description: Text("`mooringctl node new` and `node adopt` add the first node.")
            )
        } else {
            Form {
                ForEach(status.sortedNodes, id: \.id) { node in
                    NodeSection(id: node.id, row: node.row)
                }
            }
            .formStyle(.grouped)
        }
    }
}

struct NodeSection: View {
    let id: NodeId
    let row: NodeRow

    var body: some View {
        Section {
            LabeledContent("Role", value: row.role.text)
            LabeledContent("Stage", value: row.stage.text)
            LabeledContent("Generation") {
                Text(generationText)
                    .foregroundStyle(row.pendingApplySince == nil ? Color.primary : Color.orange)
            }
            verdict(.reality, row.verdicts.reality)
            verdict(.hy2, row.verdicts.hy2)
            agent
        } header: {
            Text(verbatim: id.text)
                .font(.headline)
        }
    }

    private var generationText: String {
        let applied: String
        if case .reported(let report) = row.agent, let generation = report.applied?.generation {
            applied = "\(generation)"
        } else {
            applied = String(localized: "none")
        }
        if let since = row.pendingApplySince {
            return String(
                localized:
                    "applied \(applied), current \(row.currentGeneration); pending since \(since.text) (`mooringctl node apply`)"
            )
        }
        return String(localized: "applied \(applied), current \(row.currentGeneration)")
    }

    private func verdict(_ proto: ProbeProtocol, _ result: InChainResult?) -> some View {
        LabeledContent(String(localized: "\(proto.text) in-chain probe")) {
            if let result {
                VStack(alignment: .trailing, spacing: 2) {
                    Text(result.outcome.text)
                        .foregroundStyle(result.outcome.tint)
                    Text(latencyText(result))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("not run yet")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func latencyText(_ result: InChainResult) -> String {
        if let latency = result.latencyMs {
            return String(localized: "\(latency) ms, \(result.at.text)")
        }
        return result.at.text
    }

    @ViewBuilder private var agent: some View {
        switch row.agent {
        case .notPolled:
            LabeledContent("Agent", value: String(localized: "not polled since the daemon started"))
        case .unreachable(let since, let cause):
            LabeledContent("Agent") {
                Text("unreachable since \(since.text): \(cause.text)")
                    .foregroundStyle(.red)
            }
        case .reported(let report):
            NodeReportRows(report: report)
        }
    }
}

/// What a node's agent reported.
struct NodeReportRows: View {
    let report: NodeReport

    var body: some View {
        LabeledContent("Gate") {
            Text(report.gate.text)
                .foregroundStyle(report.gate == .open ? Color.green : Color.orange)
        }
        if let holds = holdsText {
            LabeledContent("Holds", value: holds)
        }
        if let halt = report.halted {
            LabeledContent("Halted") {
                Text("\(halt.reason.text), \(halt.at.text)")
                    .foregroundStyle(.red)
            }
        }
        LabeledContent(
            "Mac's handshake",
            value: report.handshakeAgeSecs.map { String(localized: "\(span($0)) ago") }
                ?? String(localized: "none yet"))
        LabeledContent(
            "Watch",
            value: report.watchAgeSecs.map { String(localized: "\(span($0)) ago") }
                ?? String(localized: "the node's clock stepped back"))
        if !report.conditions.isEmpty {
            LabeledContent("Conditions") {
                VStack(alignment: .trailing, spacing: 2) {
                    ForEach(report.conditions, id: \.self) { condition in
                        Text(condition.text)
                            .foregroundStyle(.orange)
                    }
                }
            }
        }
        LabeledContent(
            "Accounting", value: report.accountingAt?.text ?? String(localized: "not polled yet"))
        LabeledContent("Xray") { engineText(report.engines.xray) }
        LabeledContent("Hysteria2") { engineText(report.engines.hy2) }
        LabeledContent("Host") {
            VStack(alignment: .trailing, spacing: 2) {
                Text("up \(span(report.host.uptimeSecs)), load \(loadText)")
                Text(
                    "memory free \(bytes(report.host.memAvailableBytes)), disk free \(bytes(report.host.diskFreeBytes))"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                Text(hostFlags)
                    .font(.caption)
                    .foregroundStyle(report.host.rebootRequired || !report.host.ntpSynced ? .orange : .secondary)
            }
        }
        LabeledContent(String(localized: "Transfer in \(report.transfer.month)")) {
            Text("↓ \(bytes(report.transfer.rxBytes))  ↑ \(bytes(report.transfer.txBytes))")
        }
        LabeledContent("Reported", value: report.polledAt.text)
    }

    private var holdsText: String? {
        var holds: [String] = []
        if report.holds.macDrain != nil {
            holds.append(String(localized: "the Mac's sleep drain"))
        }
        if let violation = report.holds.egressViolation {
            holds.append(String(localized: "an egress violation (\(violation.at.text))"))
        }
        if let hold = report.holds.operator {
            holds.append(String(localized: "the operator (\(hold.at.text))"))
        }
        return holds.isEmpty ? nil : ListFormatter.localizedString(byJoining: holds)
    }

    private var loadText: String {
        (Double(report.host.loadMilli) / 1000).formatted(.number.precision(.fractionLength(2)))
    }

    private var hostFlags: String {
        var flags: [String] = []
        flags.append(report.host.ntpSynced ? String(localized: "clock synchronised") : String(localized: "clock not synchronised"))
        if report.host.rebootRequired {
            flags.append(String(localized: "reboot required"))
        }
        if let upgrade = report.host.lastUnattendedUpgrade {
            flags.append(String(localized: "last upgrade \(upgrade.text)"))
        }
        return flags.joined(separator: " · ")
    }

    private func engineText(_ engine: EngineState) -> some View {
        VStack(alignment: .trailing, spacing: 2) {
            Text(engine.run.text)
            Text("restarts: \(engine.restarts)")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
