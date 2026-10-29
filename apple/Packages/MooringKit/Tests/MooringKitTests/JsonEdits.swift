// SPDX-License-Identifier: GPL-3.0-or-later

// Edits of a decoded JSON value, for the tests that put an unknown key
// into every object of a fixture.

import Foundation

enum JsonEdits {
    /// The path (keys and indices) of every object in `value`.
    static func objectPaths(_ value: Any, _ path: [Any] = []) -> [[Any]] {
        if let object = value as? [String: Any] {
            return [path] + object.keys.sorted().flatMap { objectPaths(object[$0] as Any, path + [$0]) }
        }
        if let array = value as? [Any] {
            return array.indices.flatMap { objectPaths(array[$0], path + [$0]) }
        }
        return []
    }

    /// `value` with `"zz_unknown": true` added to the object at `path`.
    static func inserting(into value: Any, at path: [Any]) -> Any {
        guard let head = path.first else {
            var object = value as? [String: Any] ?? [:]
            object["zz_unknown"] = true
            return object
        }
        let rest = Array(path.dropFirst())
        if let key = head as? String, var object = value as? [String: Any] {
            object[key] = inserting(into: object[key] as Any, at: rest)
            return object
        }
        if let index = head as? Int, var array = value as? [Any] {
            array[index] = inserting(into: array[index], at: rest)
            return array
        }
        return value
    }
}
