// SPDX-License-Identifier: GPL-3.0-or-later

// Runs `mooringctl status --follow --json --until-parent-exits` and turns
// what it prints into events (design §15.1: the CLI is the app's only
// API). Each stdout line, ended by a 0x0A byte as the CLI writes it, is
// one document; when the command ends, how it ended and what it wrote to
// stderr (its one error message) end the stream. The events carry reasons,
// not sentences: the app words them in the user's language.

import Darwin
import Foundation

/// How the command ended.
public enum EndReason: Hashable, Sendable {
    /// It exited with this code.
    case exited(Int32)
    /// A signal ended it.
    case signalled(Int32)
    /// It could not be started; the system's reason.
    case notStarted(String)
}

/// How the command ended, and what it said.
public struct StreamEnd: Error, Hashable, Sendable {
    public let reason: EndReason
    /// What the command wrote to stderr (the CLI's own words), with any
    /// failure to read its output after it.
    public let message: String

    public init(reason: EndReason, message: String) {
        self.reason = reason
        self.message = message
    }
}

/// Why a line is not shown.
public enum LineRefusal: Hashable, Sendable {
    /// The document names another version than this build reads.
    case unsupportedVersion(UInt32)
    /// The line is not a document this build reads; the decoder's reason.
    case unreadable(String)
    /// The line is longer than the CLI's own bound; the stream is ended.
    case tooLong
}

/// One event of the stream.
public enum StreamEvent: Hashable, Sendable {
    /// A document.
    case status(ConsoleStatus)
    /// A line that is not shown.
    case refused(LineRefusal)
    /// The command ended; no event follows.
    case ended(StreamEnd)
}

/// The command that prints the console's documents.
public struct StatusCommand: Sendable {
    /// The `mooringctl` to run.
    public let executable: URL

    /// Its arguments: follow the daemon's status, as JSON lines, until
    /// this app exits (however it exits, the follower ends with it).
    public static let arguments = ["status", "--follow", "--json", "--until-parent-exits"]

    /// The longest line, its newline included: the CLI's own bound on a
    /// reply line (`MAX_REPLY_LINE_BYTES` in `daemon-core::control`).
    static let lineLimit = 1 << 20

    public init(executable: URL) {
        self.executable = executable
    }

    /// The events of one run of the command. Ending the iteration early
    /// terminates the command.
    public func events() -> AsyncStream<StreamEvent> {
        AsyncStream { continuation in
            let process = Process()
            process.executableURL = executable
            process.arguments = Self.arguments
            process.standardInput = FileHandle.nullDevice
            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError = stderr
            let exit = AsyncStream<EndReason> { exited in
                process.terminationHandler = { finished in
                    exited.yield(Subprocess.reason(of: finished))
                    exited.finish()
                }
            }
            do {
                try process.run()
            } catch {
                continuation.yield(
                    .ended(StreamEnd(reason: .notStarted(error.localizedDescription), message: "")))
                continuation.finish()
                return
            }
            let reader = Task {
                async let message = Subprocess.offThePool { Subprocess.collect(stderr.fileHandleForReading) }
                let read = await Subprocess.offThePool {
                    Result { try Self.readLines(stdout.fileHandleForReading) { continuation.yield($0) } }
                }
                var readFailure: String?
                switch read {
                case .success(true):
                    break
                case .success(false):
                    // Its output can no longer be followed: stop the command,
                    // and anything still writing to the pipe.
                    process.terminate()
                    try? stdout.fileHandleForReading.close()
                case .failure(let error):
                    readFailure = "its output could not be read: \(error)"
                    process.terminate()
                    try? stdout.fileHandleForReading.close()
                }
                var reason: EndReason?
                for await ended in exit {
                    reason = ended
                }
                guard let reason else {
                    // Cancelled before the command ended: no one reads on.
                    continuation.finish()
                    return
                }
                let said = await message
                let text = [said, readFailure].compactMap { $0 }.filter { !$0.isEmpty }
                    .joined(separator: "\n")
                continuation.yield(.ended(StreamEnd(reason: reason, message: text)))
                continuation.finish()
            }
            continuation.onTermination = { _ in
                reader.cancel()
                process.terminate()
            }
        }
    }

    /// Reads `handle` to its end, blocking, a chunk at a time, and passes
    /// the event of each line, split on 0x0A bytes only, to `yield`. A line
    /// longer than `lineLimit` (its newline included) is refused as
    /// `tooLong` and ends the reading (`false`); a last line without its
    /// newline is refused as unreadable.
    static func readLines(_ handle: FileHandle, yield: (StreamEvent) -> Void) throws -> Bool {
        var buffer = [UInt8](repeating: 0, count: Subprocess.chunkBytes)
        var line: [UInt8] = []
        while true {
            let count = try Subprocess.readSome(handle, into: &buffer)
            if count == 0 {
                break
            }
            for byte in buffer[..<count] {
                if byte == 0x0A {
                    yield(event(for: line))
                    line.removeAll(keepingCapacity: true)
                } else if line.count + 1 >= lineLimit {
                    yield(.refused(.tooLong))
                    return false
                } else {
                    line.append(byte)
                }
            }
        }
        if !line.isEmpty {
            yield(.refused(.unreadable("the output ended within a line")))
        }
        return true
    }

    /// The event for one stdout line, its newline left off.
    static func event(for line: [UInt8]) -> StreamEvent {
        do {
            return .status(try ConsoleStatus.decode(line: line))
        } catch ConsoleDecodingError.unsupportedVersion(let version) {
            return .refused(.unsupportedVersion(version))
        } catch {
            return .refused(.unreadable(String(describing: error)))
        }
    }
}
