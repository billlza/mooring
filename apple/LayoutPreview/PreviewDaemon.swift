// SPDX-License-Identifier: GPL-3.0-or-later

// Test double compiled only by LayoutPreview/project.yml. The real
// DaemonService is excluded there: this host cannot register, stop or
// inspect a real daemon or open Login Items. It shows the states of the
// daemon's registration and start that the picker names, and changes
// nothing.

import MooringKit
import Observation

enum DaemonRegistration { case enabled, requiresApproval, notRegistered }

/// A state of the daemon's registration and start, for the banner above
/// the screens and the menu.
enum PreviewDaemonState: String, CaseIterable, Identifiable {
    case started = "Daemon started"
    case notStarted = "Daemon not started"
    case needsApproval = "Daemon needs approval"
    case jobNotStarted = "Apply job not started"
    case starting = "Start: waiting for launchd"
    case newBuild = "Start: a new build"
    case repairingJob = "Start: repairing the apply job"
    case daemonRefused = "Daemon refused"
    case applyJobRefused = "Apply job refused"
    case startFailed = "Start not completed"
    case untold = "Records tell nothing"

    var id: Self { self }
}

@MainActor
@Observable
final class DaemonService {
    private(set) var daemon: DaemonRegistration = .enabled
    private(set) var applyJob: DaemonRegistration = .enabled
    let openAtLogin = false
    private(set) var failure: String?
    private(set) var round: LaunchRoundPhase?
    private(set) var roundFailure: LaunchRoundFailure?
    private(set) var attention: LaunchAttention = .nothing
    private(set) var untold: [LaunchRoundFailure] = []

    func show(_ state: PreviewDaemonState) {
        daemon = .enabled
        applyJob = .enabled
        failure = nil
        round = nil
        roundFailure = nil
        attention = .nothing
        untold = []
        switch state {
        case .started:
            break
        case .notStarted:
            daemon = .notRegistered
            applyJob = .notRegistered
        case .needsApproval:
            daemon = .requiresApproval
            applyJob = .requiresApproval
        case .jobNotStarted:
            applyJob = .notRegistered
        case .starting:
            round = .starting
        case .newBuild:
            round = .newBuild
        case .repairingJob:
            round = .repairingJob
        case .daemonRefused:
            attention = .daemonRefused
        case .applyJobRefused:
            attention = .applyJobRefused
        case .startFailed:
            roundFailure = .notReplaced(.daemon)
        case .untold:
            untold = [
                .unknownState(.applyJob, "state = waiting, runs = 4, last exit code = (never exited)")
            ]
        }
    }

    func refresh() {}

    func start() { unavailable() }
    func stop() { unavailable() }
    func setOpenAtLogin(_ enabled: Bool) { unavailable() }
    func openLoginItems() { unavailable() }

    private func unavailable() {
        failure = "Layout preview: daemon and login-item actions are unavailable."
    }
}
