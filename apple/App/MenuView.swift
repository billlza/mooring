// SPDX-License-Identifier: GPL-3.0-or-later

// The menu bar item: the exit's state (once there is a deployment) and the
// router's in a line each, the console window, and Quit. Quitting the app
// leaves the daemon running (design §5.1).

import MooringKit
import SwiftUI

struct MenuView: View {
    let model: ConsoleModel
    let daemon: DaemonService
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if case (.live, .deployed(let deployed)?) = (model.state, model.status) {
            Text(String(localized: "Exit: \(deployed.exit.state.headline)"))
        }
        summary
        Divider()
        daemonItems
        Divider()
        Button("Open Console") {
            openWindow(id: ConsoleWindow.id)
            NSApp.activate()
        }
        .keyboardShortcut("o")
        Divider()
        Button("Quit Mooring") {
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q")
    }

    private var summary: Text {
        switch (model.state, model.status?.router) {
        case (.live, .available(_, let status)?):
            switch status.radio {
            case .attached(let radio):
                let rsrp =
                    radio.lte.rsrp.map { Text(verbatim: Readings.reading($0, unit: "dBm")) }
                    ?? Text("not reported")
                return Text(verbatim: "\(radio.network) \(radio.band.text) · RSRP ") + rsrp
            case .noService:
                return Text("M7: no service")
            }
        case (.live, .unavailable(let reason, _)?):
            return Text(reason.title)
        case (.live, nil), (.connecting, _):
            return Text("Waiting for the Mooring daemon…")
        case (.refusing, _):
            return Text("Not live: the latest status cannot be shown")
        case (.ended, _):
            return Text("Not live: mooringctl stopped")
        case (.stopped, _):
            return Text("Not reading the daemon's status")
        case (.noCommand, _):
            return Text("No mooringctl in this app")
        }
    }

    /// The daemon's registration and what can be done with it.
    @ViewBuilder private var daemonItems: some View {
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
        Toggle(
            "Open Mooring at Login",
            isOn: Binding(get: { daemon.openAtLogin }, set: { daemon.setOpenAtLogin($0) })
        )
        if let failure = daemon.failure {
            Text("Could not change it: \(failure)")
        }
    }
}
