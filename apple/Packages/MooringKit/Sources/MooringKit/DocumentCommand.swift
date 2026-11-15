// SPDX-License-Identifier: GPL-3.0-or-later

// Runs a one-shot `mooringctl` command and decodes the one line it prints
// (design §15.1: the CLI is the app's only API): `router history --json`
// for the Router screen, `events --json` for the Events screen. The app
// passes no dates: each command's default range, by the Mac's clock in
// UTC, is the contract, so there is one rule for the days, the CLI's. The
// command's own words (its stderr) are kept for the screen; the failures
// carry reasons and the figures they name, not sentences.

import Foundation

/// A document a one-shot `mooringctl` command prints as one JSON line.
public protocol CommandDocument: Hashable, Sendable {
    /// The command's arguments.
    static var arguments: [String] { get }
    /// The most output read, in bytes. Longer output is refused, never
    /// read in part.
    static var outputLimit: Int { get }
    /// The version of the document this build reads.
    static var version: UInt32 { get }
    /// The document of the line the command prints, with or without its
    /// newline; `ConsoleDecodingError.unsupportedVersion` for another
    /// version.
    static func decode(line: some DataProtocol) throws -> Self
}

/// Why there is no document.
public enum DocumentFailure: Error, Hashable, Sendable {
    /// The command ended without a document: it exited with an error (its
    /// own message), a signal ended it, or it could not be started.
    case ended(StreamEnd)
    /// The output is longer than `limit` bytes, the document's bound; the
    /// command was ended.
    case tooLong(limit: Int)
    /// The document is version `found`; this build reads version `reads`.
    case unsupportedVersion(found: UInt32, reads: UInt32)
    /// The output is not a document this build reads; the decoder's reason.
    case unreadable(String)
}

/// The command that prints a `Document`.
public struct DocumentCommand<Document: CommandDocument>: Sendable {
    /// The `mooringctl` to run.
    public let executable: URL

    public init(executable: URL) {
        self.executable = executable
    }

    /// One run of the command: its document, or why there is none.
    public func run() async -> Result<Document, DocumentFailure> {
        switch await Subprocess.run(executable, Document.arguments, outputLimit: Document.outputLimit) {
        case .notStarted(let why):
            return .failure(.ended(StreamEnd(reason: .notStarted(why), message: "")))
        case .tooLong:
            return .failure(.tooLong(limit: Document.outputLimit))
        case .unread(let reason, let message):
            return .failure(.ended(StreamEnd(reason: reason, message: message)))
        case .finished(let reason, var output, let said):
            guard case .exited(0) = reason else {
                return .failure(.ended(StreamEnd(reason: reason, message: said)))
            }
            if output.last == 0x0A {
                output.removeLast()
            }
            do {
                return .success(try Document.decode(line: output))
            } catch ConsoleDecodingError.unsupportedVersion(let version) {
                return .failure(.unsupportedVersion(found: version, reads: Document.version))
            } catch {
                return .failure(.unreadable(String(describing: error)))
            }
        }
    }
}
