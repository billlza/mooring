// SPDX-License-Identifier: GPL-3.0-or-later

// The daemon's registration and what can be done with it (design §5.1),
// the same in the menu bar item and in the console window's toolbar: a
// menu bar manager can hide the item, and the window still starts and
// stops the daemon. The nightly apply job's registration follows the
// daemon's (design §13.6).

import SwiftUI

struct DaemonControls: View {
    let daemon: DaemonService

    var body: some View {
        switch daemon.daemon {
        case .enabled:
            Text("Daemon: starts at login")
            Button("Stop the Daemon") { daemon.stop() }
        case .requiresApproval:
            Text("Daemon: waiting for your approval in Login Items")
            Button("Open Login Items…") { daemon.openLoginItems() }
        case .notRegistered:
            Text("Daemon: not started")
            Button("Start the Daemon at Login") { daemon.start() }
        }
        switch daemon.applyJob {
        case .enabled:
            Text("Apply job: runs nightly at 19:20 UTC")
        case .requiresApproval:
            Text("Apply job: waiting for your approval in Login Items")
        case .notRegistered:
            Text("Apply job: not started")
        }
        Toggle(
            "Open Mooring at Login",
            isOn: Binding(get: { daemon.openAtLogin }, set: { daemon.setOpenAtLogin($0) })
        )
        if let failure = daemon.failure {
            Text("Could not change it: \(failure)")
        }
    }
}
