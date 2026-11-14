// SPDX-License-Identifier: GPL-3.0-or-later

// The daemon's registration and what can be done with it (design §5.1),
// the same in the menu bar item and in the console window's toolbar: a
// menu bar manager can hide the item, and the window still starts and
// stops the daemon. The nightly apply job's registration follows the
// daemon's (design §13.6). While a start is carried through, the menu says
// what the round is doing; when macOS refuses an agent's start, it says so
// and offers the round that repairs it.

import MooringKit
import SwiftUI

struct DaemonControls: View {
    let daemon: DaemonService

    var body: some View {
        if let round = daemon.round {
            Text(round.menuLine)
            Button("Stop the Daemon") { daemon.stop() }
        } else {
            registrations
        }
        Toggle(
            "Open Mooring at Login",
            isOn: Binding(get: { daemon.openAtLogin }, set: { daemon.setOpenAtLogin($0) })
        )
        if let failure = daemon.failure {
            Text("Could not change it: \(failure)")
        }
        if let failure = daemon.roundFailure {
            Text("The start was not completed: \(failure.text)")
            if daemon.daemon == .enabled {
                Button("Try Again") { daemon.start() }
            }
        }
        ForEach(daemon.untold, id: \.self) { why in
            Text("Not checked: \(why.text)")
        }
    }

    @ViewBuilder private var registrations: some View {
        switch daemon.daemon {
        case .enabled:
            if daemon.attention == .daemonRefused {
                Text("Daemon: macOS refuses its start")
                Button("Finish Starting the Daemon") { daemon.start() }
            } else {
                Text("Daemon: starts at login")
            }
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
            if daemon.attention == .applyJobRefused {
                Text("Apply job: macOS refuses its start, so it does not run")
                Button("Repair the Apply Job") { daemon.start() }
            } else {
                Text("Apply job: runs nightly at 19:20 UTC")
            }
        case .requiresApproval:
            Text("Apply job: waiting for your approval in Login Items")
        case .notRegistered:
            Text("Apply job: not started")
            if daemon.daemon == .enabled {
                Button("Start the Apply Job") { daemon.start() }
            }
        }
    }
}
