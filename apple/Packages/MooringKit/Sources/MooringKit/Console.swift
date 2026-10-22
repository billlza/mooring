// SPDX-License-Identifier: GPL-3.0-or-later

// The console's document (`mooring-daemon-core`'s `ConsoleStatus`): one
// line of `mooringctl status --follow --json`. Before `exit init` there is
// no deployment, and the document carries the router alone.

import Foundation

/// Why a line could not be read as a console document.
public enum ConsoleDecodingError: Error, Equatable, Sendable {
    /// The document is a deployment's status, which this build of the app
    /// does not show yet: its mirror of `MacStatusV1` is not built, so it
    /// refuses the document rather than show part of it.
    case deploymentNotShown
    /// The undeployed document names another version than 1.
    case unsupportedVersion(UInt32)
}

/// The status before a deployment exists: when the daemon made it, and the
/// router panel.
public struct UndeployedStatus: Decodable, Hashable, Sendable {
    /// The version this build reads.
    public static let version: UInt32 = 1

    public let at: UnixTime
    public let router: RouterReading

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, at, router
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        let version = try object.decode(UInt32.self, forKey: .version)
        guard version == Self.version else {
            throw ConsoleDecodingError.unsupportedVersion(version)
        }
        at = try object.decode(UnixTime.self, forKey: .at)
        router = try object.decode(RouterReading.self, forKey: .router)
    }
}

/// What the console shows. This build shows the undeployed document only;
/// a deployment's is refused with `deploymentNotShown`.
public enum ConsoleStatus: Decodable, Hashable, Sendable {
    case noDeployment(UndeployedStatus)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.onlyKey()
        switch tag {
        case "no_deployment":
            self = .noDeployment(try UndeployedStatus(from: value))
        case "deployed":
            throw ConsoleDecodingError.deploymentNotShown
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    /// One line of the stream, without or with its newline.
    public static func decode(line: some DataProtocol) throws -> ConsoleStatus {
        try JSONDecoder().decode(ConsoleStatus.self, from: Data(line))
    }

    /// The router panel.
    public var router: RouterReading {
        switch self {
        case .noDeployment(let status): status.router
        }
    }

    /// When the daemon made the document.
    public var at: UnixTime {
        switch self {
        case .noDeployment(let status): status.at
        }
    }
}
