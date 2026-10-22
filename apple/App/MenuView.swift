// SPDX-License-Identifier: GPL-3.0-or-later

// The menu bar item: the router's state in a line, the console window, and
// Quit. Quitting the app leaves the daemon running (design §5.1).

import MooringKit
import SwiftUI

struct MenuView: View {
    let model: ConsoleModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        summary
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
        case (.ended, _):
            return Text("Not live: mooringctl stopped")
        case (.noCommand, _):
            return Text("No mooringctl in this app")
        }
    }
}
