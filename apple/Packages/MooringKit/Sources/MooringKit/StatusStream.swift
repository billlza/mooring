// SPDX-License-Identifier: GPL-3.0-or-later

// Runs `mooringctl status --follow --json` and turns what it prints into
// events (design §15.1: the CLI is the app's only API). Each stdout line
// is one document; when the command ends, its exit code and what it wrote
// to stderr (its one error message) end the stream.

import Foundation

/// How the command ended.
public struct StreamEnd: Error, Hashable, Sendable {
    /// The exit code, or `nil` when the command could not be started.
    public let exitCode: Int32?
    /// What the command wrote to stderr, or why it could not be started.
    public let message: String
}

/// One event of the stream.
public enum StreamEvent: Hashable, Sendable {
    /// A document.
    case status(ConsoleStatus)
    /// A line that is not a document this build shows.
    case refused(String)
    /// The command ended; no event follows.
    case ended(StreamEnd)
}

/// The command that prints the console's documents.
public struct StatusCommand: Sendable {
    /// The `mooringctl` to run.
    public let executable: URL

    /// Its arguments: follow the daemon's status, as JSON lines.
    public static let arguments = ["status", "--follow", "--json"]

    /// The most of stderr kept: the CLI writes one error and its causes.
    static let stderrLimit = 16 * 1024

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
            let exit = AsyncStream<Int32> { exited in
                process.terminationHandler = { finished in
                    exited.yield(finished.terminationStatus)
                    exited.finish()
                }
            }
            do {
                try process.run()
            } catch {
                continuation.yield(
                    .ended(
                        StreamEnd(
                            exitCode: nil,
                            message: "cannot start \(executable.path): \(error.localizedDescription)"
                        )))
                continuation.finish()
                return
            }
            let reader = Task {
                async let message = Self.collect(stderr.fileHandleForReading)
                var readFailure: String?
                do {
                    for try await line in stdout.fileHandleForReading.bytes.lines {
                        continuation.yield(Self.event(for: line))
                    }
                } catch {
                    readFailure = "its output could not be read: \(error)"
                }
                var code: Int32?
                for await status in exit {
                    code = status
                }
                let said = await message
                let text = [said, readFailure].compactMap { $0 }.filter { !$0.isEmpty }
                    .joined(separator: "\n")
                continuation.yield(.ended(StreamEnd(exitCode: code, message: text)))
                continuation.finish()
            }
            continuation.onTermination = { _ in
                reader.cancel()
                process.terminate()
            }
        }
    }

    /// The event for one stdout line.
    static func event(for line: String) -> StreamEvent {
        do {
            return .status(try ConsoleStatus.decode(line: Data(line.utf8)))
        } catch ConsoleDecodingError.deploymentNotShown {
            return .refused(
                "The daemon reports a deployment, which this build of Mooring.app does not show yet.")
        } catch ConsoleDecodingError.unsupportedVersion(let version) {
            return .refused("The daemon's document is version \(version); this build reads version 1.")
        } catch {
            return .refused("A line from mooringctl could not be read: \(error)")
        }
    }

    /// Stderr, up to `stderrLimit` bytes, as text.
    static func collect(_ handle: FileHandle) async -> String {
        var bytes: [UInt8] = []
        do {
            for try await byte in handle.bytes where bytes.count < stderrLimit {
                bytes.append(byte)
            }
        } catch {
            bytes.append(contentsOf: Array("\n(stderr could not be read: \(error))".utf8))
        }
        return String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
