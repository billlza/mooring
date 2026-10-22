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
                Group {
                    switch screen {
                    case .overview: OverviewView(model: model)
                    case .router: RouterView(model: model)
                    case let other: NeedsDeploymentView(screen: other)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .navigationTitle(Text(screen.title))
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

/// Where the stream stands, above every screen: live with the time of the
/// last document, or why it is not.
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
        case .connecting: "hourglass"
        case .ended, .noCommand: "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch model.state {
        case .live: .green
        case .connecting: .secondary
        case .ended, .noCommand: .orange
        }
    }

    private var headline: LocalizedStringKey {
        switch model.state {
        case .live: "Live from the Mooring daemon"
        case .connecting: "Waiting for the Mooring daemon…"
        case .ended: "Not live: mooringctl stopped"
        case .noCommand: "This app carries no mooringctl"
        }
    }

    private func detail(now: Date) -> String? {
        var parts: [String] = []
        if let received = model.receivedAt {
            parts.append(String(localized: "Last status \(received.formatted(date: .omitted, time: .standard))"))
        }
        switch model.state {
        case .ended(let end, let retryAt):
            let seconds = max(0, Int(retryAt.timeIntervalSince(now).rounded(.up)))
            parts.append(end.message.isEmpty ? String(localized: "It ended without a message.") : end.message)
            parts.append(String(localized: "Retrying in \(seconds) s."))
        case .noCommand(let path):
            parts.append(String(localized: "Expected at \(path)."))
        case .connecting where model.status == nil:
            parts.append(
                String(
                    localized:
                        "The daemon reports after its first poll of the M7, which waits while macOS asks you to allow keychain or local network access."
                ))
        case .live, .connecting:
            break
        }
        if let refusal = model.refusal {
            parts.append(refusal)
        }
        return parts.isEmpty ? nil : parts.joined(separator: "  ·  ")
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
