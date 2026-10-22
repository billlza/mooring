// SPDX-License-Identifier: GPL-3.0-or-later

// Mooring.app (design §5.1, §15): the operator's console. It runs only the
// `mooringctl` inside its own bundle, reads `status --follow --json`, and
// never touches a secret or a daemon file. It is a menu-bar app
// (LSUIElement); the console window opens at launch and from the menu.

import MooringKit
import SwiftUI

@main
struct MooringApp: App {
    @State private var model = ConsoleModel.forMainBundle()

    var body: some Scene {
        Window("Mooring", id: ConsoleWindow.id) {
            ConsoleView(model: model)
                .frame(minWidth: 780, minHeight: 540)
                .task { model.start() }
        }
        .defaultSize(width: 980, height: 680)

        MenuBarExtra {
            MenuView(model: model)
        } label: {
            Image(systemName: model.menuSymbol)
        }
    }
}

enum ConsoleWindow {
    static let id = "console"
}

extension ConsoleModel {
    /// The model for the `mooringctl` this app carries
    /// (`Contents/MacOS/mooringctl`), or one that says it is missing.
    static func forMainBundle() -> ConsoleModel {
        if let executable = Bundle.main.url(forAuxiliaryExecutable: "mooringctl") {
            return ConsoleModel(command: StatusCommand(executable: executable))
        }
        return ConsoleModel(
            command: nil,
            missing: Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/mooringctl").path)
    }

    /// The menu bar's symbol: the router's state at a glance.
    var menuSymbol: String {
        switch (state, status?.router) {
        case (.live, .available?): "antenna.radiowaves.left.and.right"
        case (.live, .unavailable?): "antenna.radiowaves.left.and.right.slash"
        default: "exclamationmark.triangle"
        }
    }
}
