// SPDX-License-Identifier: GPL-3.0-or-later

// The console window (design §15.3): a sidebar of the console's screens.
// Before a deployment exists only the overview and the router have
// anything to show; every other screen says what it needs, rather than
// showing empty figures for a deployment that does not exist.

import MooringKit
import SwiftUI

enum Screen: String, CaseIterable, Identifiable {
    case overview, router, users, nodes, exit, sim, capacity, events

    var id: Self { self }

    var title: LocalizedStringKey {
        switch self {
        case .overview: "Overview"
        case .router: "Router"
        case .users: "Users"
        case .nodes: "Nodes"
        case .exit: "Exit"
        case .sim: "SIM"
        case .capacity: "Capacity"
        case .events: "Events"
        }
    }

    var symbol: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .router: "antenna.radiowaves.left.and.right"
        case .users: "person.2"
        case .nodes: "server.rack"
        case .exit: "arrow.up.right.circle"
        case .sim: "simcard"
        case .capacity: "speedometer"
        case .events: "list.bullet.rectangle"
        }
    }
}

struct ConsoleView: View {
    let model: ConsoleModel
    let daemon: DaemonService
    /// The screen shown, kept across launches.
    @AppStorage("screen") private var screen: Screen = .overview

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
                    case (.router, _): RouterView(model: model)
                    case (.users, let deployed?): UsersView(status: deployed)
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

/// Where the stream stands, above every screen: live with the time the
/// daemon made the document shown, or why it is not live.
struct StreamBanner: View {
    let model: ConsoleModel

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(spacing: 8) {
                Image(systemName: symbol)
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(headline)
                        .font(.callout.weight(.semibold))
                    if let detail = detail(now: context.date) {
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(tint.opacity(0.08))
        }
    }

    private var symbol: String {
        switch model.state {
        case .live: "dot.radiowaves.left.and.right"
        case .connecting, .stopped: "hourglass"
        case .refusing, .ended, .noCommand: "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch model.state {
        case .live: .green
        case .connecting, .stopped: .secondary
        case .refusing, .ended, .noCommand: .orange
        }
    }

    private var headline: LocalizedStringKey {
        switch model.state {
        case .live: "Live from the Mooring daemon"
        case .connecting: "Waiting for the Mooring daemon…"
        case .refusing: "Not live: the latest status cannot be shown"
        case .ended: "Not live: mooringctl stopped"
        case .stopped: "Not reading the daemon's status"
        case .noCommand: "This app carries no mooringctl"
        }
    }

    private func detail(now: Date) -> String? {
        var parts: [String] = []
        if let at = model.status?.at {
            parts.append(String(localized: "Status from \(at.date.formatted(date: .omitted, time: .standard))"))
        }
        switch model.state {
        case .ended(let end, let retryAt):
            let seconds = max(0, Int(retryAt.timeIntervalSince(now).rounded(.up)))
            parts.append(end.text)
            parts.append(String(localized: "Retrying in \(seconds) s."))
        case .refusing(let refusal):
            parts.append(refusal.text)
        case .noCommand(let path):
            parts.append(String(localized: "Expected at \(path)."))
        case .connecting where model.status == nil:
            parts.append(
                String(
                    localized:
                        "The daemon reports after its first poll of the M7, which waits while macOS asks you to allow keychain or local network access."
                ))
        case .live, .connecting, .stopped:
            break
        }
        return parts.isEmpty ? nil : parts.joined(separator: "  ·  ")
    }
}

extension StreamEnd {
    /// How the command ended, in the user's language, then what it said
    /// (`mooringctl`'s own words).
    var text: String {
        let how =
            switch reason {
            case .exited(let code): String(localized: "mooringctl exited with code \(code).")
            case .signalled(let signal): String(localized: "mooringctl was ended by signal \(signal).")
            case .notStarted(let why): String(localized: "mooringctl could not be started: \(why)")
            }
        return message.isEmpty ? how : "\(how) \(message)"
    }
}

extension LineRefusal {
    /// Why the latest line is not shown, in the user's language.
    var text: String {
        switch self {
        case .unsupportedVersion(let version):
            String(localized: "The daemon's document is version \(version); this build reads version 1.")
        case .unreadable(let why):
            String(localized: "A line from mooringctl could not be read: \(why)")
        case .tooLong:
            String(localized: "A line from mooringctl was longer than 1 MiB, so the app stopped reading it.")
        }
    }
}

/// The daemon's registration, above every screen while it does not run at
/// login: not started, or waiting for the operator's approval
/// (`AgentNotEnabled`, design §5.1). Nothing is shown once it is enabled.
struct DaemonBanner: View {
    let daemon: DaemonService
    @Environment(\.scenePhase) private var phase

    var body: some View {
        Group {
            switch daemon.daemon {
            case .enabled:
                EmptyView()
            case .requiresApproval:
                notice(
                    "Mooring's daemon needs your approval",
                    "macOS lists it under System Settings › General › Login Items; turn it on there.",
                    action: "Open Login Items…",
                    perform: daemon.openLoginItems
                )
            case .notRegistered:
                notice(
                    "Mooring's daemon is not started",
                    "It reads the M7 and runs the exit. Started here, it runs at every login until stopped from the menu.",
                    action: "Start the Daemon at Login",
                    perform: daemon.start
                )
            }
        }
        .onChange(of: phase) { _, now in
            if now == .active {
                daemon.refresh()
            }
        }
    }

    private func notice(
        _ title: LocalizedStringKey,
        _ detail: LocalizedStringKey,
        action: LocalizedStringKey,
        perform: @escaping () -> Void
    ) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.callout.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let failure = daemon.failure {
                    Text("Could not change it: \(failure)")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            Button(action, action: perform)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.08))
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
