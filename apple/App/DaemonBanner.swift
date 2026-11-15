// SPDX-License-Identifier: GPL-3.0-or-later

import MooringKit
import SwiftUI

/// The daemon's registration and start, above every screen while there is
/// something to say of them (design §5.1): not started, or waiting for the
/// operator's approval (`AgentNotEnabled`); the daemon registered without
/// the apply job; a start being carried through; one that was not
/// completed; an agent whose start macOS refuses, as after a new build; or
/// launchd's records telling the app nothing. Nothing is shown while both
/// agents are registered and macOS lets them start.
struct DaemonBanner: View {
    let daemon: DaemonService
    @Environment(\.scenePhase) private var phase

    var body: some View {
        Group {
            if let round = daemon.round {
                notice(Text(round.title), Text(round.detail), working: true)
            } else {
                switch (daemon.daemon, daemon.applyJob) {
                case (.enabled, .enabled):
                    registered
                case (.requiresApproval, _), (.enabled, .requiresApproval):
                    notice(
                        Text("Mooring's daemon needs your approval"),
                        Text("macOS lists it under System Settings › General › Login Items; turn it on there."),
                        action: "Open Login Items…"
                    ) { daemon.openLoginItems() }
                case (.notRegistered, _):
                    notice(
                        Text("Mooring's daemon is not started"),
                        Text(
                            "It reads the M7 and runs the exit. Started here, it runs at every login until stopped from the menu."
                        ),
                        action: "Start the Daemon at Login"
                    ) { daemon.start() }
                case (.enabled, .notRegistered):
                    notice(
                        Text("The nightly apply job is not started"),
                        Text(
                            "The daemon is registered and the job is not, so the night's suspensions, resumes and node applies do not happen."
                        ),
                        action: "Start the Apply Job"
                    ) { daemon.start() }
                }
            }
        }
        .onChange(of: phase) { _, now in
            if now == .active {
                daemon.refresh()
            }
        }
    }

    /// Both agents are registered and allowed: what their start still asks
    /// of the operator, if anything.
    @ViewBuilder private var registered: some View {
        if daemon.roundFailure != nil {
            notice(
                Text("The start of the daemon and the apply job was not completed"),
                Text("The steps by hand are in `docs/runbooks/console.md`, sections 1 and 7."),
                action: "Try Again"
            ) { daemon.start() }
        } else {
            switch daemon.attention {
            case .daemonRefused:
                notice(
                    Text("macOS refuses the daemon's start"),
                    Text(
                        "It does so after a new build is installed, until its record of the registration is replaced. Finishing the start takes up to a minute and a half: the app waits for the daemon's second start, starts the nightly apply job twice, and registers both again."
                    ),
                    action: "Finish Starting"
                ) { daemon.start() }
            case .applyJobRefused:
                notice(
                    Text("The nightly apply job does not run"),
                    Text(
                        "macOS refuses its start, as it does after a new build until the job is registered again, so the night's suspensions, resumes and node applies do not happen. The repair takes up to a minute; it stops the daemon for a few seconds and restarts the exit with it, because both are registered again."
                    ),
                    action: "Repair the Apply Job"
                ) { daemon.start() }
            case .nothing:
                if !daemon.untold.isEmpty {
                    notice(
                        Text("Not checked whether macOS lets the daemon and the apply job start"),
                        Text(daemon.untold.map(\.text).joined(separator: " ")),
                        action: "Check Again"
                    ) { daemon.refresh() }
                }
            }
        }
    }

    private func notice(_ title: Text, _ detail: Text, working: Bool = false) -> some View {
        notice(title, detail, working: working) { EmptyView() }
    }

    private func notice(
        _ title: Text, _ detail: Text, action: LocalizedStringKey, perform: @escaping () -> Void
    ) -> some View {
        notice(title, detail, working: false) { Button(action, action: perform) }
    }

    private func notice(
        _ title: Text, _ detail: Text, working: Bool, @ViewBuilder button: () -> some View
    ) -> some View {
        HStack(spacing: 8) {
            if working {
                ProgressView()
                    .controlSize(.small)
            } else {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            VStack(alignment: .leading, spacing: 2) {
                title
                    .font(.callout.weight(.semibold))
                detail
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let failure = daemon.failure {
                    Text("Could not change it: \(failure)")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
                if let failure = daemon.roundFailure {
                    Text("The start was not completed: \(failure.text)")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            button()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.08))
    }
}
