// SPDX-License-Identifier: GPL-3.0-or-later

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
