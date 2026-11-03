// SPDX-License-Identifier: GPL-3.0-or-later

// Paths into a JSON value read with `JSONSerialization`, edits at them,
// and the two walks the strict decoding is tested with: an unknown key
// added to each object of a document in turn, and each key of each record
// removed in turn, every edited document required to be refused.

import Foundation
import Testing

enum JSONPaths {
    /// Every object in `value`, with its path (keys and indices); with
    /// `skippingMaps`, the objects under those keys are left out, though
    /// the objects inside their entries are kept.
    static func objects(
        in value: Any, skippingMaps maps: Set<String> = [], at path: [Any] = []
    ) -> [(path: [Any], object: [String: Any])] {
        if let object = value as? [String: Any] {
            let isMap = (path.last as? String).map(maps.contains) ?? false
            let inner = object.keys.sorted().flatMap { key in
                objects(in: object[key] as Any, skippingMaps: maps, at: path + [key])
            }
            return isMap ? inner : [(path, object)] + inner
        }
        if let array = value as? [Any] {
            return array.indices.flatMap { objects(in: array[$0], skippingMaps: maps, at: path + [$0]) }
        }
        return []
    }

    /// `value` with the object at `path` changed by `edit`. A path that
    /// does not lead to an object is a test's mistake, and fails it.
    static func editing(
        _ value: Any,
        at path: [Any],
        sourceLocation: SourceLocation = #_sourceLocation,
        _ edit: (inout [String: Any]) -> Void
    ) throws -> Any {
        guard let head = path.first else {
            var object = try #require(
                value as? [String: Any], "the path does not end at an object", sourceLocation: sourceLocation)
            edit(&object)
            return object
        }
        let rest = Array(path.dropFirst())
        if let key = head as? String {
            var object = try #require(value as? [String: Any], "no object holds \(key)", sourceLocation: sourceLocation)
            let inner = try #require(object[key], "no key \(key)", sourceLocation: sourceLocation)
            object[key] = try editing(inner, at: rest, sourceLocation: sourceLocation, edit)
            return object
        }
        let index = try #require(
            head as? Int, "a step of the path is neither a key nor an index", sourceLocation: sourceLocation)
        var array = try #require(value as? [Any], "no array holds \(index)", sourceLocation: sourceLocation)
        try #require(array.indices.contains(index), "no index \(index)", sourceLocation: sourceLocation)
        array[index] = try editing(array[index], at: rest, sourceLocation: sourceLocation, edit)
        return array
    }

    /// Requires `decode` to read `json` as it is, and to refuse it once
    /// `"zz_unknown": true` is added to any one of its objects; in a map
    /// keyed by ids, the key reads as an entry whose value is refused.
    /// Returns how many objects were tried, so that a caller can tell a
    /// walk that stopped at the top.
    @discardableResult
    static func expectEveryObjectRefusesAnUnknownKey(
        in json: Any,
        sourceLocation: SourceLocation = #_sourceLocation,
        decode: (Data) throws -> Void
    ) throws -> Int {
        try decode(try Fixtures.encode(json))
        let found = objects(in: json)
        for (path, _) in found {
            let edited = try Fixtures.encode(
                try editing(json, at: path, sourceLocation: sourceLocation) { $0["zz_unknown"] = true })
            #expect(throws: (any Error).self, "accepted an unknown key at \(path)", sourceLocation: sourceLocation) {
                try decode(edited)
            }
        }
        return found.count
    }

    /// Requires `decode` to read `json` as it is, and to refuse it once any
    /// one key, one whose value is `null` included, is removed from any one
    /// of its records: every object but those under `maps`, which are keyed
    /// by the deployment's ids. Returns how many keys were removed, and how
    /// many of them held `null`.
    @discardableResult
    static func expectEveryKeyIsRequired(
        in json: Any,
        skippingMaps maps: Set<String> = [],
        sourceLocation: SourceLocation = #_sourceLocation,
        decode: (Data) throws -> Void
    ) throws -> (removed: Int, nulls: Int) {
        try decode(try Fixtures.encode(json))
        var removed = 0
        var nulls = 0
        for (path, object) in objects(in: json, skippingMaps: maps) {
            for key in object.keys.sorted() {
                removed += 1
                if object[key] is NSNull {
                    nulls += 1
                }
                let edited = try Fixtures.encode(
                    try editing(json, at: path, sourceLocation: sourceLocation) { $0.removeValue(forKey: key) })
                #expect(
                    throws: (any Error).self, "accepted a missing \(key) at \(path)", sourceLocation: sourceLocation
                ) {
                    try decode(edited)
                }
            }
        }
        return (removed, nulls)
    }
}
