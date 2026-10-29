// SPDX-License-Identifier: GPL-3.0-or-later

// Runs `mooringctl router history --json` once and decodes the one line it
// prints (design §15.1: the CLI is the app's only API). The CLI's default
// range, yesterday and today in UTC by the Mac's clock, is the contract:
// the app passes no dates and takes the last 24 hours from the samples'
// times, so there is one rule for the days, the CLI's. The command's own
// words (its stderr) are kept for the screen; the failures carry reasons,
// not sentences.

import Foundation

/// Why there is no history document.
public enum HistoryFailure: Error, Hashable, Sendable {
    /// The command ended without a document: it exited with an error (its
    /// own message), a signal ended it, or it could not be started.
    case ended(StreamEnd)
    /// The output is longer than the bound; the command was ended.
    case tooLong
    /// The document names another version than this build reads.
    case unsupportedVersion(UInt32)
    /// The output is not a document this build reads; the decoder's reason.
    case unreadable(String)
}

/// The command that prints the history document.
public struct HistoryCommand: Sendable {
    /// The `mooringctl` to run.
    public let executable: URL

    /// Its arguments: the document of the CLI's default range.
    public static let arguments = ["router", "history", "--json"]

    /// The most output read: the two days of the default range are at most
    /// 2 × 1440 lines of under 400 bytes, about 1.2 MB, with the events
    /// after them; 4 MiB leaves room for an M7 polled oftener. Longer
    /// output is refused, never read in part.
    static let outputLimit = 4 << 20

    public init(executable: URL) {
        self.executable = executable
    }

    /// One run of the command: its document, or why there is none.
    public func run() async -> Result<RadioHistory, HistoryFailure> {
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
            return .failure(.ended(StreamEnd(reason: .notStarted(error.localizedDescription), message: "")))
        }
        async let message = Subprocess.offThePool { Subprocess.collect(stderr.fileHandleForReading) }
        let read = await Subprocess.offThePool {
            Result { try Subprocess.readAll(stdout.fileHandleForReading, limit: Self.outputLimit) }
        }
        if case .success(.some) = read {
        } else {
            // Its output cannot be used, so nothing more is read: the command
            // is ended, and anything still writing to the pipe with it.
            process.terminate()
            try? stdout.fileHandleForReading.close()
        }
        var reason: EndReason = .exited(0)
        for await ended in exit {
            reason = ended
        }
        let said = await message
        switch read {
        case .success(nil):
            return .failure(.tooLong)
        case .failure(let error):
            let text = [said, "its output could not be read: \(error)"].filter { !$0.isEmpty }
            return .failure(.ended(StreamEnd(reason: reason, message: text.joined(separator: "\n"))))
        case .success(var output?):
            guard case .exited(0) = reason else {
                return .failure(.ended(StreamEnd(reason: reason, message: said)))
            }
            if output.last == 0x0A {
                output.removeLast()
            }
            do {
                return .success(try RadioHistory.decode(line: output))
            } catch ConsoleDecodingError.unsupportedVersion(let version) {
                return .failure(.unsupportedVersion(version))
            } catch {
                return .failure(.unreadable(String(describing: error)))
            }
        }
    }
}
