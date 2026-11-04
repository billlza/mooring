// SPDX-License-Identifier: GPL-3.0-or-later

// A Debug-only visual regression host. It compiles the actual App views,
// decodes the repository's fixture with the actual decoder, and supplies
// events directly to the model. It runs no subprocess and reads no live
// daemon, network, keychain or deployment state.

import Foundation
import SwiftUI

@testable import MooringKit

enum ConsoleWindow { static let id = "layout-preview" }

private enum Scenario: String, CaseIterable, Identifiable {
    case usageUnavailable = "Usage unavailable"
    case report = "Usage report"
    case noUsers = "No users"
    case retryCountdown = "Retry countdown"

    var id: Self { self }

    @MainActor func apply(to model: ConsoleModel) throws {
        model.apply(.status(try status()))
        if self == .retryCountdown {
            model.apply(.ended(StreamEnd(reason: .exited(7), message: "Layout fixture")))
        }
    }

    func status() throws -> ConsoleStatus {
        guard let url = Bundle.main.url(forResource: "serving", withExtension: "json") else {
            throw PreviewError.missingFixture
        }
        let data = try Data(contentsOf: url)
        guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PreviewError.invalidFixture
        }
        if self == .usageUnavailable {
            object["usage"] = ["unavailable": ["reason": "MissingLedger"]]
            guard var users = object["users"] as? [String: [String: Any]] else {
                throw PreviewError.invalidFixture
            }
            for id in Array(users.keys) { users[id]?["usage"] = NSNull() }
            object["users"] = users
        } else if self == .noUsers {
            object["users"] = [String: Any]()
        }
        let changed = try JSONSerialization.data(withJSONObject: object)
        return .deployed(try JSONDecoder().decode(DeployedStatus.self, from: changed))
    }
}

private enum PreviewError: Error { case missingFixture, invalidFixture }

@main
struct LayoutPreviewApp: App {
    @State private var scenario: Scenario = .usageUnavailable
    @State private var model: ConsoleModel
    @State private var history = HistoryModel(command: nil)
    @State private var daemon = DaemonService()

    init() {
        // This bundle has its own preferences domain.
        UserDefaults.standard.set("users", forKey: "screen")
        let model = ConsoleModel(command: nil)
        do {
            try Scenario.usageUnavailable.apply(to: model)
        } catch {
            preconditionFailure("Invalid layout fixture: \(error)")
        }
        _model = State(initialValue: model)
    }

    var body: some Scene {
        Window("Mooring Layout Preview", id: ConsoleWindow.id) {
            ConsoleView(model: model, daemon: daemon, history: history)
                .frame(minWidth: 780, minHeight: 540)
                .toolbar {
                    Picker("Fixture", selection: $scenario) {
                        ForEach(Scenario.allCases) { scenario in
                            Text(verbatim: scenario.rawValue).tag(scenario)
                        }
                    }
                }
                .onChange(of: scenario) { _, next in
                    do {
                        try next.apply(to: model)
                    } catch {
                        preconditionFailure("Invalid layout fixture: \(error)")
                    }
                }
        }
        .defaultSize(width: 980, height: 680)
    }
}
