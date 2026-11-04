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
    @Binding var selection: UserId?

    var body: some View {
        VStack(spacing: 0) {
            usageBanner
            if status.users.isEmpty {
                ContentUnavailableView(
                    "No users",
                    systemImage: "person.2",
                    description: Text("`mooringctl user add` adds the first user.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(rows, selection: $selection) {
                    TableColumn("User") { row in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(verbatim: row.row.alias ?? row.id.text)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if row.row.alias != nil {
                                Text(verbatim: row.id.text)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
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
                        Text(cycleFigure(row))
                    }
                    .width(min: 130, ideal: 170)
                }

            }
        }
    }

    private var rows: [UserListRow] {
        status.sortedUsers.map { UserListRow(id: $0.id, row: $0.row) }
    }

    /// Whether the daemon pulled no usage, so no figure is read.
    private var usageNotPulled: Bool {
        if case .notPulled = status.usage { true } else { false }
    }

    /// The row's bytes this cycle, or that none were read or none are
    /// available.
    private func cycleFigure(_ row: UserListRow) -> String {
        usageNotPulled ? String(localized: "not read") : figure(row.row.usage?.cycle)
    }

    @ViewBuilder private var usageBanner: some View {
        switch status.usage {
        case .report(let periods):
            caption(Text("Usage through \(periods.through.text), cycle from \(periods.cycle.start.display)."))
        case .unavailable(let reason):
            Label("Usage unavailable: \(reason.text).", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
        case .notPulled:
            caption(Text("Usage is not read by this build yet; status and activity are live."))
        }
    }

    /// A line of secondary text above the table.
    private func caption(_ text: Text) -> some View {
        text
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 6)
    }
}
