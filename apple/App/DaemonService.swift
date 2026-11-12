// SPDX-License-Identifier: GPL-3.0-or-later

// The daemon as a login item (design §5.1, M7): Mooring.app registers the
// LaunchAgent its bundle carries (`Contents/Library/LaunchAgents/
// com.bill.mooring.daemon.plist`) with SMAppService, so launchd runs the
// bundle's `mooringctl daemon` at login and keeps it running. Beside it,
// the app registers the nightly apply job (`com.bill.mooring.apply.plist`,
// design §13.6), which launchd runs every hour at minute 20 as
// `mooringctl apply --pending`; starting and stopping the daemon starts and
// stops both. When macOS wants the operator's approval first, the console
// says so (`AgentNotEnabled`) and opens Login Items. The app itself can be
// a login item too, so the console opens at login.

import Observation
import ServiceManagement

/// The daemon's registration, as the app shows it.
enum DaemonRegistration: Equatable {
    /// Registered and allowed: launchd runs the daemon.
    case enabled
    /// Registered, but macOS waits for the operator's approval in Login
    /// Items (`AgentNotEnabled`, design §5.1).
    case requiresApproval
    /// Not registered: the daemon does not run at login.
    case notRegistered

    init(_ status: SMAppService.Status) {
        switch status {
        case .enabled: self = .enabled
        case .requiresApproval: self = .requiresApproval
        // Measured 2026-10-23 on macOS 27.0: a never-registered agent
        // reports `.notFound`, one unregistered since `.notRegistered`.
        case .notRegistered, .notFound: self = .notRegistered
        @unknown default: self = .notRegistered
        }
    }
}

@MainActor
@Observable
final class DaemonService {
    /// The daemon's plist in the app's bundle.
    static let plistName = "com.bill.mooring.daemon.plist"
    /// The nightly apply job's plist in the app's bundle.
    static let applyPlistName = "com.bill.mooring.apply.plist"

    private(set) var daemon: DaemonRegistration
    private(set) var applyJob: DaemonRegistration
    private(set) var openAtLogin: Bool
    /// What the last change failed with, in the system's words.
    private(set) var failure: String?

    private let agent = SMAppService.agent(plistName: DaemonService.plistName)
    private let applyAgent = SMAppService.agent(plistName: DaemonService.applyPlistName)

    init() {
        daemon = DaemonRegistration(agent.status)
        applyJob = DaemonRegistration(applyAgent.status)
        openAtLogin = SMAppService.mainApp.status == .enabled
    }

    /// Reads the registrations again: Login Items may have changed them.
    func refresh() {
        daemon = DaemonRegistration(agent.status)
        applyJob = DaemonRegistration(applyAgent.status)
        openAtLogin = SMAppService.mainApp.status == .enabled
    }

    /// Registers the daemon, then the apply job: launchd starts the daemon
    /// now and at every login, and the job every hour at minute 20.
    func start() {
        change {
            try agent.register()
            try applyAgent.register()
        }
    }

    /// Unregisters the daemon, then the apply job if it is registered (an
    /// app built before the job registered none): launchd stops the
    /// daemon, and starts neither again.
    func stop() {
        change {
            try agent.unregister()
            if DaemonRegistration(applyAgent.status) != .notRegistered {
                try applyAgent.unregister()
            }
        }
    }

    /// Makes the app a login item, or stops it being one.
    func setOpenAtLogin(_ open: Bool) {
        change {
            if open {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        }
    }

    /// Opens System Settings at Login Items, where the operator approves
    /// the daemon.
    func openLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }

    private func change(_ work: () throws -> Void) {
        do {
            try work()
            failure = nil
        } catch {
            failure = error.localizedDescription
        }
        refresh()
    }
}
