// SPDX-License-Identifier: GPL-3.0-or-later

// The contract fixtures the Rust tests generate and pin byte for byte
// (`contract/console-fixtures/`, `contract/status-fixtures/variants.json`),
// read from the repository.

import Foundation

enum Fixtures {
    /// The repository's root: five levels above this file
    /// (`apple/Packages/MooringKit/Tests/MooringKitTests/`).
    static let root: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    static func data(_ relative: String) throws -> Data {
        try Data(contentsOf: root.appendingPathComponent(relative))
    }

    static func console(_ name: String) throws -> Data {
        try data("contract/console-fixtures/\(name).json")
    }

    /// `data` as a JSON value, to edit.
    static func json(_ data: Data) throws -> Any {
        try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    /// `value` written back as JSON.
    static func encode(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
    }
}
