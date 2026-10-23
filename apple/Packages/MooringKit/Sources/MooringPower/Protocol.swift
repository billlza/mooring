// SPDX-License-Identifier: GPL-3.0-or-later

// The power helper's protocol (`mooring-daemon-core`'s `power` module,
// design §5.1, §10.3): the helper writes one event per line on its stdout
// and reads one command per line on its stdin. The events are written
// exactly as the Rust types encode them, and the commands are read as
// strictly as the Rust types decode them (`contract/power-fixtures/`).

import Foundation

/// The longest line either side writes, its newline included.
public let maxHelperLineBytes = 256

/// The helper's own limit on a sleep the daemon has not answered: past it
/// the sleep proceeds, inside IOKit's 30 s window.
public let allowSleepAfter: Duration = .seconds(25)

/// Where the Mac's power comes from.
public enum PowerSourceValue: String, Sendable, Equatable {
    case ac
    case battery
}

/// What the helper tells the daemon.
public enum HelperEvent: Equatable, Sendable {
    case powerSource(PowerSourceValue)
    case assertions(held: Bool)
    case willSleep(id: UInt64)
    case didWake

    /// The event's line, newline included, as the daemon reads it.
    public var line: String {
        switch self {
        case .powerSource(let source): "{\"power_source\":\"\(source.rawValue)\"}\n"
        case .assertions(let held): "{\"assertions\":{\"held\":\(held)}}\n"
        case .willSleep(let id): "{\"will_sleep\":{\"id\":\(id)}}\n"
        case .didWake: "\"did_wake\"\n"
        }
    }
}

/// What the daemon tells the helper.
public enum HelperCommand: Equatable, Sendable {
    /// Hold (`true`) or release (`false`) the two assertions.
    case hold(Bool)
    /// Let the sleep `id` proceed.
    case allowSleep(id: UInt64)

    /// Why a line is not a command.
    public enum Refusal: Error, Equatable, Sendable {
        case tooLong
        case notACommand
    }

    /// One command line, with or without its newline: one JSON object with
    /// one known key, holding exactly what that command holds.
    public static func decode(line: some DataProtocol) throws(Refusal) -> HelperCommand {
        var bytes = Array(line)
        guard bytes.count <= maxHelperLineBytes else {
            throw .tooLong
        }
        if bytes.last == 0x0A {
            bytes.removeLast()
        }
        guard !bytes.contains(0x0A),
            let decoded = try? JSONDecoder().decode(CommandLine.self, from: Data(bytes))
        else {
            throw .notACommand
        }
        return decoded.command
    }
}

/// Any key, to list every key an object has.
private struct Key: CodingKey {
    let stringValue: String
    init(_ stringValue: String) { self.stringValue = stringValue }
    init?(stringValue: String) { self.stringValue = stringValue }
    var intValue: Int? { nil }
    init?(intValue: Int) { nil }
}

/// A command as one JSON object, refusing any other key.
private struct CommandLine: Decodable {
    let command: HelperCommand

    init(from decoder: any Decoder) throws {
        let object = try decoder.container(keyedBy: Key.self)
        guard object.allKeys.count == 1, let key = object.allKeys.first else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "one key expected"))
        }
        switch key.stringValue {
        case "hold":
            command = .hold(try object.decode(Bool.self, forKey: key))
        case "allow_sleep":
            let fields = try object.nestedContainer(keyedBy: Key.self, forKey: key)
            guard fields.allKeys.map(\.stringValue) == ["id"] else {
                throw DecodingError.dataCorrupted(
                    DecodingError.Context(codingPath: [key], debugDescription: "only id expected"))
            }
            command = .allowSleep(id: try fields.decode(UInt64.self, forKey: Key("id")))
        default:
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [key], debugDescription: "unknown command"))
        }
    }
}
