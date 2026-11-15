// SPDX-License-Identifier: GPL-3.0-or-later

// Mooring.app (design §5.1, §15): the operator's console. It runs the
// `mooringctl` inside its own bundle, reads `status --follow --json` and,
// for the Router screen, `router history --json`, and never touches a
// secret or a daemon file. The one other program it runs is the system's
// `/bin/launchctl`, for its own two launch agents only: it reads launchd's
// records of them and, while a start is carried through after a new build,
// starts the apply job (DaemonService). It is a menu-bar app (LSUIElement);
// the console window opens at launch and from the menu, which raises it in
// front of other apps' windows (ConsoleWindowFront).

import MooringKit
import SwiftUI

@main
struct MooringApp: App {
    @State private var model: ConsoleModel
    @State private var history: HistoryModel
    @State private var daemon = DaemonService()
    @State private var consoleFront = ConsoleWindowFront()

    /// The model reads from launch, whether or not the window is shown: the
    /// menu bar's summary needs it too. The history is read when the
    /// Router screen asks.
    init() {
        let model = ConsoleModel.forMainBundle()
        model.start()
        _model = State(initialValue: model)
        _history = State(initialValue: HistoryModel.forMainBundle())
    }

    var body: some Scene {
        Window("Mooring", id: ConsoleWindow.id) {
            ConsoleView(model: model, daemon: daemon, history: history)
                .frame(minWidth: 780, minHeight: 540)
                .background(
                    HostingWindowReader { [consoleFront] window in
                        consoleFront.attach(AppKitRaisableWindow(window: window))
                    })
        }
        .defaultSize(width: 980, height: 680)

        MenuBarExtra {
            MenuView(model: model, daemon: daemon, consoleFront: consoleFront)
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

}

extension HistoryModel {
    /// The model for the `mooringctl` this app carries, or one that says it
    /// is missing.
    static func forMainBundle() -> HistoryModel {
        HistoryModel(command: Bundle.main.url(forAuxiliaryExecutable: "mooringctl").map(HistoryCommand.init))
    }
}

extension ConsoleModel {
    /// The menu bar's symbol: the exit's state at a glance once there is a
    /// deployment, and the router's before.
    var menuSymbol: String {
        switch (state, status) {
        case (.live, .deployed(let deployed)?):
            switch deployed.exit.state {
            case .serving: "antenna.radiowaves.left.and.right"
            case .degraded: "exclamationmark.circle"
            case .down: "xmark.octagon"
            case .disabled, .paused: "pause.circle"
            case .preflight, .starting, .verifying: "hourglass"
            }
        case (.live, .noDeployment(let undeployed)?):
            switch undeployed.router {
            case .available: "antenna.radiowaves.left.and.right"
            case .unavailable: "antenna.radiowaves.left.and.right.slash"
            }
        default: "exclamationmark.triangle"
        }
    }
}
