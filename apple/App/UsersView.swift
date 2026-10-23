// SPDX-License-Identifier: GPL-3.0-or-later

// The users screen (design §15.3): one row per user by opaque id and
// public alias (labels stay in `state.json`), with the lifecycle state,
// activity, bytes for today, the SIM cycle, the calendar month and
// lifetime, the quota and the expiry. When the daemon has no usage report
// the figures say so, never zeros.

import MooringKit
import SwiftUI

struct UsersView: View {
    let status: DeployedStatus
    @State private var selection: UserId?

    var body: some View {
        VStack(spacing: 0) {
            usageBanner
            if status.users.isEmpty {
                ContentUnavailableView(
                    "No users",
                    systemImage: "person.2",
                    description: Text("`mooringctl user add` adds the first user.")
                )
            } else {
                Table(rows, selection: $selection) {
                    TableColumn("User") { row in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(verbatim: row.row.alias ?? row.id.text)
                            if row.row.alias != nil {
                                Text(verbatim: row.id.text)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(min: 110, ideal: 140)
                    TableColumn("Status") { row in
                        Text(row.row.status.shortText)
                            .foregroundStyle(row.row.status.tint)
                            .help(row.row.status.text)
                    }
                    .width(min: 70, ideal: 90)
                    TableColumn("Activity") { row in
                        Text(row.row.activity.activeNow.text)
                    }
                    .width(min: 60, ideal: 80)
                    TableColumn("This cycle") { row in
                        Text(figure(row.row.usage?.cycle))
                    }
                    .width(min: 130, ideal: 170)
                }
                .inspector(isPresented: inspectorShown) {
                    if let row = rows.first(where: { $0.id == selection }) {
                        UserDetail(row: row)
                            .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
                    }
                }
            }
        }
    }

    private var rows: [UserListRow] {
        status.sortedUsers.map { UserListRow(id: $0.id, row: $0.row) }
    }

    /// The inspector shows the selected user, and closing it clears the
    /// selection.
    private var inspectorShown: Binding<Bool> {
        Binding(
            get: { selection != nil },
            set: { if !$0 { selection = nil } }
        )
    }

    @ViewBuilder private var usageBanner: some View {
        switch status.usage {
        case .report(let periods):
            Text("Usage through \(periods.through.text), cycle from \(periods.cycle.start.display).")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
        case .unavailable(let reason):
            Label("Usage unavailable: \(reason.text).", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
        }
    }
}

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
                LabeledContent("Quota", value: row.row.quota.text)
                LabeledContent("Expiry", value: row.row.expiry.text)
            }
        }
        .formStyle(.grouped)
    }
}
