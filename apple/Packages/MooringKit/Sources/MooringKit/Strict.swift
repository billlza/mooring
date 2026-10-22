// SPDX-License-Identifier: GPL-3.0-or-later

// Strict decoding: the console's documents are Rust types with
// `deny_unknown_fields` and closed enums (design §15.2), so the mirror
// refuses what they refuse. An object with a key its type does not name is
// an error, a value the Rust type spells as `Option` with a required key
// must be present (as `null` when it is none), and an externally tagged
// enum is an object with exactly one known key.

import Foundation

/// A coding key for any string, to list every key an object has.
struct AnyKey: CodingKey {
    let stringValue: String

    init(_ stringValue: String) {
        self.stringValue = stringValue
    }

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    var intValue: Int? { nil }

    init?(intValue: Int) {
        nil
    }
}

extension Decoder {
    /// The object's container keyed by `Key`, once every key it has is one
    /// `Key` names.
    func strictContainer<Key: CodingKey & CaseIterable>(
        keyedBy type: Key.Type
    ) throws -> KeyedDecodingContainer<Key> {
        let every = try container(keyedBy: AnyKey.self)
        let known = Set(Key.allCases.map(\.stringValue))
        if let unknown = every.allKeys.first(where: { !known.contains($0.stringValue) }) {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: codingPath + [unknown],
                    debugDescription: "unknown key \(unknown.stringValue)"
                )
            )
        }
        return try container(keyedBy: Key.self)
    }

    /// The one key of an externally tagged enum's object, and a decoder for
    /// its value.
    func onlyKey() throws -> (tag: String, value: any Decoder) {
        let object = try container(keyedBy: AnyKey.self)
        guard object.allKeys.count == 1, let key = object.allKeys.first else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: codingPath,
                    debugDescription: "expected one key, found \(object.allKeys.count)"
                )
            )
        }
        return (key.stringValue, try object.superDecoder(forKey: key))
    }

    /// The error for a tag or a string no variant has.
    func unknownVariant(_ tag: String) -> DecodingError {
        DecodingError.dataCorrupted(
            DecodingError.Context(codingPath: codingPath, debugDescription: "unknown variant \(tag)")
        )
    }
}

extension KeyedDecodingContainer {
    /// A value whose key must be present and whose value may be `null`.
    /// `decodeNil(forKey:)` throws `keyNotFound` for a missing key, so a
    /// missing key is refused here as the Rust type refuses it; only an
    /// explicit `null` is none.
    func decodeNullable<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T? {
        if try decodeNil(forKey: key) {
            return nil
        }
        return try decode(T.self, forKey: key)
    }
}
