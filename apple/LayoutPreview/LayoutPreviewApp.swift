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
    case latchedViolation = "Latched violation"
    case latchBehindAnotherReason = "Latch behind another reason"
    case simChanged = "SIM changed"
    case networkChanged = "Network changed, same SIM name"
    case noNetworkOnRecord = "No network on record yet"
    case networkTaken = "Network taken at the operator's word"

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
        } else if self == .latchedViolation || self == .latchBehindAnotherReason {
            guard var exit = object["exit"] as? [String: Any], let since = exit["since"] as? UInt64 else {
                throw PreviewError.invalidFixture
            }
            // Found 36 h before the state last became this one, as when
            // another reason held the exit down in front of the latch.
            let violation = ["outside_carrier_prefixes": ["ip": "203.0.113.9"]]
            exit["latches"] = [["violation": violation, "at": since - 130_091] as [String: Any]]
            exit["carrier_check"] = NSNull()
            if self == .latchedViolation {
                exit["state"] = ["down": ["reason": ["violation": violation]]]
            } else {
                // Preflight finds the foreign network before the latch.
                let findings: [[String: Any]] = [
                    ["routable_ipv4": ["interface": "en0"]],
                    ["default_route": ["interface": "en0", "family": "v4"]],
                ]
                exit["state"] = ["down": ["reason": ["foreign_network_attached": ["findings": findings]]]]
                exit["foreign_networks"] = findings
            }
            object["exit"] = exit
        } else if self == .simChanged || self == .networkChanged || self == .noNetworkOnRecord
            || self == .networkTaken
        {
            guard var sim = object["sim"] as? [String: Any], var network = sim["network"] as? [String: Any],
                let at = object["at"] as? UInt64
            else {
                throw PreviewError.invalidFixture
            }
            if self == .noNetworkOnRecord {
                // The record could not be read, and no poll has found the
                // M7 attached since.
                network["origin"] = "record_unreadable"
                network["baseline"] = NSNull()
            } else if self == .networkTaken {
                guard var baseline = network["baseline"] as? [String: Any] else {
                    throw PreviewError.invalidFixture
                }
                // `mooringctl sim accept-network` took the fixture's network
                // ten minutes before the status, and the M7 still reports it.
                network["origin"] = "accepted"
                baseline["first_seen"] = at - 600
                network["baseline"] = baseline
            } else {
                guard var baseline = network["baseline"] as? [String: Any] else {
                    throw PreviewError.invalidFixture
                }
                // The fixture's baseline is a SIM without a name on 234-20.
                // Another SIM: a name, on another network, as on 2026-11-11.
                // The same name: no name either, on another network.
                let spn: Any = self == .simChanged ? "1p" : NSNull()
                let mnc = self == .simChanged ? "30" : "10"
                let reported: [String: Any] = ["spn": spn, "plmn": ["mcc": "234", "mnc": mnc]]
                baseline["other"] = ["network": reported, "since": at - 68_400] as [String: Any]
                network["baseline"] = baseline
            }
            sim["network"] = network
            object["sim"] = sim
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
    @State private var daemonState: PreviewDaemonState = .started

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
                    Picker("Daemon", selection: $daemonState) {
                        ForEach(PreviewDaemonState.allCases) { state in
                            Text(verbatim: state.rawValue).tag(state)
                        }
                    }
                }
                .onChange(of: daemonState) { _, next in
                    daemon.show(next)
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
