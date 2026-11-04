// SPDX-License-Identifier: GPL-3.0-or-later

// The console window (design §15.3): a sidebar of the console's screens.
// Before a deployment exists only the overview and the router have
// anything to show; every other screen says what it needs, rather than
// showing empty figures for a deployment that does not exist.

import MooringKit
import SwiftUI

struct ConsoleView: View {
    let model: ConsoleModel
    let daemon: DaemonService
    let history: HistoryModel
    /// The screen shown, kept across launches.
    @AppStorage("screen") private var screen: Screen = .overview
    @State private var selectedUser: UserId?

    var body: some View {
        NavigationSplitView {
            List(Screen.allCases, selection: selection) { screen in
                Label(screen.title, systemImage: screen.symbol)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            VStack(spacing: 0) {
                StreamBanner(model: model)
                DaemonBanner(daemon: daemon)
                Group {
                    switch (screen, model.status?.deployed) {
                    case (.overview, _): OverviewView(model: model)
                    case (.router, _): RouterView(model: model, history: history)
                    case (.users, let deployed?): UsersView(status: deployed, selection: $selectedUser)
                    case (.nodes, let deployed?): NodesView(status: deployed)
                    case (.exit, let deployed?): ExitView(status: deployed)
                    case (.sim, let deployed?): SimView(status: deployed)
                    case (.capacity, let deployed?): CapacityView(status: deployed)
                    case (.events, _?): EventsNotBuiltView()
                    case (let other, nil): NeedsDeploymentView(screen: other)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            // An inspector is a column of the window, not of the nested table.
            // Attaching it to the table makes AppKit draw another titlebar at
            // the table's origin on macOS 27.2, covering the header and first row.
            .inspector(isPresented: inspectorShown) {
                if let deployed = model.status?.deployed,
                    let id = selectedUser, let row = deployed.users[id]
                {
                    UserDetail(row: UserListRow(id: id, row: row), usage: deployed.usage)
                        .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
                }
            }
            .navigationTitle(Text(screen.title))
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        DaemonControls(daemon: daemon)
                    } label: {
                        Label("Daemon", systemImage: "gearshape.2")
                    }
                    .help("Start or stop Mooring's daemon")
                }
            }
        }
        .onChange(of: screen) { _, next in
            if next != .users { selectedUser = nil }
        }
        .onChange(of: model.status?.deployed?.users.keys.sorted()) { _, ids in
            if let selectedUser, ids?.contains(selectedUser) != true {
                self.selectedUser = nil
            }
        }
    }

    /// Only an existing user on the Users screen can own the inspector.
    /// Closing it clears the table selection as well.
    private var inspectorShown: Binding<Bool> {
        Binding(
            get: {
                screen == .users && selectedUser.map { model.status?.deployed?.users[$0] != nil } == true
            },
            set: { if !$0 { selectedUser = nil } }
        )
    }

    /// The list's selection: a screen is always selected, so deselecting
    /// keeps the current one.
    private var selection: Binding<Screen?> {
        Binding(
            get: { screen },
            set: { if let chosen = $0 { screen = chosen } }
        )
    }
}

/// The events screen: the event journals are not read by this build.
struct EventsNotBuiltView: View {
    var body: some View {
        ContentUnavailableView {
            Label("Events", systemImage: "list.bullet.rectangle")
        } description: {
            Text(
                "The Mac's and the nodes' event journals are not read by this build yet; the open alerts are on the overview."
            )
        }
    }
}

/// A screen that needs a deployment.
struct NeedsDeploymentView: View {
    let screen: Screen

    var body: some View {
        ContentUnavailableView {
            Label(screen.title, systemImage: screen.symbol)
        } description: {
            Text(
                "This screen fills in once a deployment exists on this Mac. `mooringctl exit init` creates it; until then the console shows the M7 router only."
            )
        }
    }
}
