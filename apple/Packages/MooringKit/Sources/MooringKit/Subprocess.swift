// SPDX-License-Identifier: GPL-3.0-or-later

// What running a command as a child process needs, shared by the status
// stream and the commands that run once (the history, and `launchctl` for
// the app's own agents): a pipe read off the concurrency pool, one read(2)
// at a time, stderr collected within a bound, how a finished process ended,
// and one run of a command to its end.

import Darwin
import Foundation

enum Subprocess {
    /// The most one read takes from a pipe.
    static let chunkBytes = 64 * 1024

    /// The most of stderr kept: the CLI writes one error and its causes.
    static let stderrLimit = 16 * 1024

    /// How one run of a command to its end went.
    enum Run: Sendable {
        /// It could not be started; the system's reason.
        case notStarted(String)
        /// Its output passed the bound: it was ended, and none of the output
        /// is kept.
        case tooLong
        /// Its output could not be read, and it was ended: how it ended, and
        /// its stderr with the read's failure after it.
        case unread(EndReason, String)
        /// It ended: how, its whole output, and its stderr.
        case finished(EndReason, [UInt8], String)
    }

    /// Runs `executable` with `arguments` once, with no input, to its end:
    /// its output within `outputLimit` bytes, and its stderr.
    static func run(_ executable: URL, _ arguments: [String], outputLimit: Int) async -> Run {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
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
            return .notStarted(error.localizedDescription)
        }
        async let message = Subprocess.offThePool { Subprocess.collect(stderr.fileHandleForReading) }
        let read = await Subprocess.offThePool {
            Result { try Subprocess.readAll(stdout.fileHandleForReading, limit: outputLimit) }
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
            return .tooLong
        case .failure(let error):
            let text = [said, "its output could not be read: \(error)"].filter { !$0.isEmpty }
            return .unread(reason, text.joined(separator: "\n"))
        case .success(let output?):
            return .finished(reason, output, said)
        }
    }

    /// Runs `work` on a thread of its own: a pipe read blocks, which must
    /// not hold one of the concurrency pool's few threads.
    static func offThePool<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { finished in
            Thread { finished.resume(returning: work()) }.start()
        }
    }

    /// How a finished process ended.
    static func reason(of process: Process) -> EndReason {
        switch process.terminationReason {
        case .uncaughtSignal: .signalled(process.terminationStatus)
        case .exit: .exited(process.terminationStatus)
        @unknown default: .exited(process.terminationStatus)
        }
    }

    /// One read(2) into `buffer`: how many bytes came, 0 at the end. It
    /// returns as soon as some have come, where `FileHandle.read(upToCount:)`
    /// waits on a pipe for the whole count or the end, which a follower
    /// that stays running never gives.
    static func readSome(_ handle: FileHandle, into buffer: inout [UInt8]) throws -> Int {
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(handle.fileDescriptor, bytes.baseAddress, bytes.count)
            }
            if count >= 0 {
                return count
            }
            guard errno == EINTR else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
    }

    /// Reads `handle` to its end, blocking: the bytes, or `nil` as soon as
    /// they pass `limit` (nothing more is read; the caller ends the command).
    static func readAll(_ handle: FileHandle, limit: Int) throws -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: chunkBytes)
        var kept: [UInt8] = []
        while true {
            let count = try readSome(handle, into: &buffer)
            if count == 0 {
                return kept
            }
            if kept.count + count > limit {
                return nil
            }
            kept.append(contentsOf: buffer[..<count])
        }
    }

    /// Stderr, up to `stderrLimit` bytes, as text. It reads, blocking, to
    /// the end past the limit, so a command that writes more never blocks
    /// on the pipe.
    static func collect(_ handle: FileHandle) -> String {
        var buffer = [UInt8](repeating: 0, count: chunkBytes)
        var kept: [UInt8] = []
        do {
            while true {
                let count = try readSome(handle, into: &buffer)
                if count == 0 {
                    break
                }
                kept.append(contentsOf: buffer[..<count].prefix(max(0, stderrLimit - kept.count)))
            }
        } catch {
            kept.append(contentsOf: Array("\n(stderr could not be read: \(error))".utf8))
        }
        return String(decoding: kept, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
