// SPDX-License-Identifier: GPL-3.0-or-later

// Test double compiled only by LayoutPreview/project.yml. The real
// DaemonService is excluded there: this host cannot register, stop or
// inspect a real daemon or open Login Items.

import Observation

enum DaemonRegistration { case enabled, requiresApproval, notRegistered }

@MainActor
@Observable
final class DaemonService {
    let daemon: DaemonRegistration = .enabled
    let applyJob: DaemonRegistration = .enabled
    let openAtLogin = false
    private(set) var failure: String?

    func refresh() {}

    func start() { unavailable() }
    func stop() { unavailable() }
    func setOpenAtLogin(_ enabled: Bool) { unavailable() }
    func openLoginItems() { unavailable() }

    private func unavailable() {
        failure = "Layout preview: daemon and login-item actions are unavailable."
    }
}
