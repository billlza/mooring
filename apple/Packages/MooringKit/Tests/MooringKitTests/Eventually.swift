// SPDX-License-Identifier: GPL-3.0-or-later

// Waiting for a model that runs a stand-in `mooringctl` to reach a state.

import Foundation

/// Waits up to 10 s for `condition`, asked on the main actor.
@MainActor
func eventually(_ condition: @MainActor () -> Bool) async throws -> Bool {
    let deadline = Date().addingTimeInterval(10)
    while Date() < deadline {
        if condition() {
            return true
        }
        try await Task.sleep(for: .milliseconds(20))
    }
    return condition()
}
