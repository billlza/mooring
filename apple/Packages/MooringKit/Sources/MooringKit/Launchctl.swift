// SPDX-License-Identifier: GPL-3.0-or-later

// `/bin/launchctl` for the app's own two agents (design §5.1): what launchd
// holds for one (`print`), and a start by hand (`kickstart`). SMAppService
// tells only whether an agent is registered, not whether macOS lets its
// program start, so the app reads launchd's record as the operator does
// with the runbook. Nothing else is asked of launchd, and no other service
// is named.

import Darwin
import Foundation

/// Why `launchctl` gave nothing to go on.
public enum LaunchctlFailure: Error, Hashable, Sendable {
    /// It ended otherwise than the request allows, or could not be started;
    /// the arguments it was given, how it ended, and its own words.
    case ended(arguments: [String], StreamEnd)
    /// It printed more than the bound; the arguments it was given.
    case tooLong(arguments: [String])
    /// It was still running at the time limit, and was ended; the arguments
    /// it was given.
    case overdue(arguments: [String])
    /// Its printout is not one this build reads; the service, and why.
    case unreadable(service: String, LaunchRecordError)
}

/// `launchctl`, for the services of the user's own login session.
public struct Launchctl: Sendable {
    /// The system's `launchctl`.
    public static let system = URL(fileURLWithPath: "/bin/launchctl")

    /// `launchctl print`'s exit code for a service that launchd does not
    /// list.
    static let notListed: Int32 = 113

    /// The most output read: a service's printout is about 3 kB.
    public static let outputLimit = 256 * 1024

    /// The longest one run is waited for. launchd answered within a tenth of
    /// a second whenever it was measured; a run still going after this is
    /// ended, so that what waits for it has a bound when launchd does not
    /// answer at all.
    public static let timeLimit: Duration = .seconds(10)

    /// The `launchctl` to run.
    public let executable: URL
    /// The user's domain, `gui/<uid>`.
    public let domain: String
    /// How long one run may take before it is ended.
    public let timeLimit: Duration

    /// `launchctl` for the user `uid`, this process's own unless a test
    /// names another, each run within `timeLimit`.
    public init(
        executable: URL = Launchctl.system, uid: uid_t = getuid(), timeLimit: Duration = Launchctl.timeLimit
    ) {
        self.executable = executable
        self.domain = "gui/\(uid)"
        self.timeLimit = timeLimit
    }

    /// The service target of `label`, `gui/<uid>/<label>`.
    public func service(_ label: String) -> String {
        "\(domain)/\(label)"
    }

    /// launchd's record of `label`, or `nil` when launchd does not list it.
    public func record(of label: String) async throws(LaunchctlFailure) -> LaunchRecord? {
        let target = service(label)
        let arguments = ["print", target]
        let (reason, output, said) = try await finished(arguments)
        switch reason {
        case .exited(0):
            do {
                return try LaunchRecord(printed: String(decoding: output, as: UTF8.self))
            } catch {
                throw .unreadable(service: target, error)
            }
        case .exited(Self.notListed):
            return nil
        default:
            throw .ended(arguments: arguments, StreamEnd(reason: reason, message: said))
        }
    }

    /// Asks launchd to start `label` now. launchd answers before the start
    /// succeeds or is refused: the record tells which.
    public func kickstart(_ label: String) async throws(LaunchctlFailure) {
        let arguments = ["kickstart", service(label)]
        let (reason, _, said) = try await finished(arguments)
        guard case .exited(0) = reason else {
            throw .ended(arguments: arguments, StreamEnd(reason: reason, message: said))
        }
    }

    /// One run to its end: how it ended, what it printed and its stderr.
    private func finished(_ arguments: [String]) async throws(LaunchctlFailure) -> (EndReason, [UInt8], String) {
        let run = await Subprocess.run(executable, arguments, outputLimit: Self.outputLimit, timeLimit: timeLimit)
        switch run {
        case nil:
            throw .overdue(arguments: arguments)
        case .notStarted(let why):
            throw .ended(arguments: arguments, StreamEnd(reason: .notStarted(why), message: ""))
        case .tooLong:
            throw .tooLong(arguments: arguments)
        case .unread(let reason, let message):
            throw .ended(arguments: arguments, StreamEnd(reason: reason, message: message))
        case .finished(let reason, let output, let said):
            return (reason, output, said)
        }
    }
}
