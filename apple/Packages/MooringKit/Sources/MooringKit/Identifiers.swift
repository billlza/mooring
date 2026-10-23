// SPDX-License-Identifier: GPL-3.0-or-later

// The names a deployment's status uses for its nodes, its users and its
// days (`mooring-model`'s `NodeId`, `UserId` and `CalendarDate`). Their
// spelling is the Rust types' to check; the mirror keeps the text, and
// orders it as the Rust maps do (byte order).

import Foundation

/// A node's id, such as `lon1`.
public struct NodeId: Hashable, Comparable, Sendable, Decodable, CodingKeyRepresentable {
    public let text: String

    public init(_ text: String) {
        self.text = text
    }

    public init(from decoder: any Decoder) throws {
        text = try decoder.singleValueContainer().decode(String.self)
    }

    public init?<T: CodingKey>(codingKey: T) {
        text = codingKey.stringValue
    }

    public var codingKey: any CodingKey {
        AnyKey(text)
    }

    public static func < (lhs: NodeId, rhs: NodeId) -> Bool {
        Array(lhs.text.utf8).lexicographicallyPrecedes(Array(rhs.text.utf8))
    }
}

/// A user's opaque id. Labels stay in `state.json`; the status never
/// carries one (design §15.5).
public struct UserId: Hashable, Comparable, Sendable, Decodable, CodingKeyRepresentable {
    public let text: String

    public init(_ text: String) {
        self.text = text
    }

    public init(from decoder: any Decoder) throws {
        text = try decoder.singleValueContainer().decode(String.self)
    }

    public init?<T: CodingKey>(codingKey: T) {
        text = codingKey.stringValue
    }

    public var codingKey: any CodingKey {
        AnyKey(text)
    }

    public static func < (lhs: UserId, rhs: UserId) -> Bool {
        Array(lhs.text.utf8).lexicographicallyPrecedes(Array(rhs.text.utf8))
    }
}

/// A UTC calendar day, `YYYY-MM-DD`.
public struct CalendarDate: Hashable, Comparable, Sendable, Decodable {
    public let text: String

    public init(_ text: String) {
        self.text = text
    }

    public init(from decoder: any Decoder) throws {
        text = try decoder.singleValueContainer().decode(String.self)
    }

    /// `YYYY-MM-DD` orders as its days do.
    public static func < (lhs: CalendarDate, rhs: CalendarDate) -> Bool {
        lhs.text < rhs.text
    }
}
