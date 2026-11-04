// SPDX-License-Identifier: GPL-3.0-or-later

import MooringKit
import SwiftUI

/// A row of the users table.
struct UserListRow: Identifiable {
    let id: UserId
    let row: UserRow
}

/// Down and up, or that there are no figures.
func figure(_ traffic: Traffic?) -> String {
    guard let traffic else {
        return String(localized: "unavailable")
    }
    return "↓ \(bytes(traffic.downlink))  ↑ \(bytes(traffic.uplink))"
}

/// One user's figures in full.
struct UserDetail: View {
    let row: UserListRow
    /// Whether the daemon pulled no usage, so a quota's usage is not read
    /// rather than unavailable.
    let usage: UsageView

    var body: some View {
        Form {
            Section {
                LabeledContent("Opaque id", value: row.id.text)
                LabeledContent("Alias", value: row.row.alias ?? String(localized: "none"))
                LabeledContent("Status", value: row.row.status.text)
                LabeledContent(
                    "Nodes",
                    value: row.row.nodes.isEmpty
                        ? String(localized: "none")
                        : ListFormatter.localizedString(byJoining: row.row.nodes.map(\.text)))
                LabeledContent("Activity", value: row.row.activity.activeNow.text)
                LabeledContent(
                    "Last seen", value: row.row.activity.lastSeen?.text ?? String(localized: "never"))
            }
            if let usage = row.row.usage {
                Section {
                    LabeledContent("Today", value: figure(usage.today))
                    LabeledContent("This cycle", value: figure(usage.cycle))
                    LabeledContent("This month", value: figure(usage.month))
                    LabeledContent("Lifetime", value: figure(usage.lifetime))
                    LabeledContent("Served this cycle", value: bytes(usage.cycleServedBytes))
                    LabeledContent("REALITY this cycle", value: figure(usage.cycleByProtocol.reality))
                    LabeledContent("Hysteria2 this cycle", value: figure(usage.cycleByProtocol.hy2))
                    ForEach(usage.cycleByNode.sorted { $0.key < $1.key }, id: \.key) { node, traffic in
                        LabeledContent(String(localized: "On \(node.text) this cycle"), value: figure(traffic))
                    }
                } header: {
                    Text("Usage")
                } footer: {
                    if row.row.accuracy.realityDownlinkCountedAtClose {
                        Text("REALITY downloads are counted when their connection closes, so a long one shows late.")
                    }
                }
            }
            Section("Limits") {
                LabeledContent("Quota", value: quotaText)
                LabeledContent("Expiry", value: row.row.expiry.text)
            }
        }
        .formStyle(.grouped)
    }

    /// The quota, which with no usage pulled reads as not read rather than
    /// unavailable.
    private var quotaText: String {
        if case .notPulled = usage, case .usageUnavailable(let quota) = row.row.quota {
            return String(localized: "Quota \(bytes(quota)); usage not read")
        }
        return row.row.quota.text
    }
}
