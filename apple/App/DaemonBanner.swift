// SPDX-License-Identifier: GPL-3.0-or-later

import MooringKit
import SwiftUI

/// The daemon's registration, above every screen while it does not run at
/// login: not started, or waiting for the operator's approval
/// (`AgentNotEnabled`, design §5.1). Nothing is shown once it is enabled.
struct DaemonBanner: View {
    let daemon: DaemonService
    @Environment(\.scenePhase) private var phase

    var body: some View {
        Group {
            switch daemon.daemon {
            case .enabled:
                EmptyView()
            case .requiresApproval:
                notice(
                    "Mooring's daemon needs your approval",
                    "macOS lists it under System Settings › General › Login Items; turn it on there.",
                    action: "Open Login Items…",
                    perform: daemon.openLoginItems
                )
            case .notRegistered:
                notice(
                    "Mooring's daemon is not started",
                    "It reads the M7 and runs the exit. Started here, it runs at every login until stopped from the menu.",
                    action: "Start the Daemon at Login",
                    perform: daemon.start
                )
            }
        }
        .onChange(of: phase) { _, now in
            if now == .active {
                daemon.refresh()
            }
        }
    }

    private func notice(
        _ title: LocalizedStringKey,
        _ detail: LocalizedStringKey,
        action: LocalizedStringKey,
        perform: @escaping () -> Void
    ) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.callout.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let failure = daemon.failure {
                    Text("Could not change it: \(failure)")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            Button(action, action: perform)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.08))
    }
}
