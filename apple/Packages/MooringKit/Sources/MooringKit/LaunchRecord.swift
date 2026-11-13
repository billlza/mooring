// SPDX-License-Identifier: GPL-3.0-or-later

// What launchd holds for one of the app's two launch agents, the daemon and
// the nightly apply job (design §5.1): the lines of `launchctl print
// gui/<uid>/<label>` that tell whether macOS lets the agent's program start.
//
// macOS pins a registration to the program's code signature, an ad-hoc one
// by its cdhash, so after a new build is installed it refuses the agent's
// start until its record of the registration is replaced, which it does at
// the agent's own second failed start and no sooner; a registration made
// after that finds the new record. The printout is not an interface: these
// are the lines macOS 27.2 printed on 2026-11-13, and a printout without
// them is refused, never guessed at.

import Foundation

/// The two agents Mooring.app registers.
public enum LaunchAgent: Hashable, Sendable, CaseIterable {
    /// `mooringctl daemon`, which launchd starts at once and keeps running.
    case daemon
    /// `mooringctl apply --pending`, which launchd starts every hour.
    case applyJob
}

/// The agent's `last exit code` line.
public enum LaunchLastExit: Hashable, Sendable {
    /// `(never exited)`.
    case never
    /// An exit code, printed as `0` or as `78: EX_CONFIG`.
    case code(Int32)
    /// Anything else, as printed.
    case other(String)
}

/// Why a printout is not read.
public enum LaunchRecordError: Error, Hashable, Sendable {
    /// It does not begin as a service's printout does (`<target> = {`); its
    /// first line.
    case notAPrintout(String)
    /// It has no line for this key.
    case missing(String)
    /// The line for a key the record needs cannot be read; the line.
    case unreadable(String)
}

/// launchd's record of an agent: the lines of its printout that the app
/// reads, each the service's own (one tab in). The blocks nested in the
/// printout repeat some of the keys further in, and are not read.
public struct LaunchRecord: Hashable, Sendable {
    /// `state`: `running`, `not running`, `spawn scheduled`.
    public let state: String
    /// `runs`: how often launchd has started the agent, or tried to, since
    /// it was registered.
    public let runs: Int
    /// `last exit code`, which a printout made after a first refused start
    /// does not have.
    public let lastExit: LaunchLastExit?
    /// `job state`: `running`, `exited`, `spawn failed`, `uninitialized`.
    public let jobState: String?
    /// `properties`, such as `needs LWCR update` and `has LWCR`.
    public let properties: [String]

    public init(state: String, runs: Int, lastExit: LaunchLastExit?, jobState: String?, properties: [String]) {
        self.state = state
        self.runs = runs
        self.lastExit = lastExit
        self.jobState = jobState
        self.properties = properties
    }

    /// Reads what `launchctl print` wrote for one service.
    public init(printed: String) throws(LaunchRecordError) {
        let lines = printed.split(separator: "\n", omittingEmptySubsequences: false)
        guard let first = lines.first, first.hasSuffix(" = {"), first.first?.isWhitespace == false else {
            throw LaunchRecordError.notAPrintout(String(printed.prefix(120)))
        }
        var values: [String: String] = [:]
        for line in lines.dropFirst() {
            guard line.hasPrefix("\t"), !line.hasPrefix("\t\t"),
                let separator = line.range(of: " = ")
            else {
                continue
            }
            let key = String(line[line.index(after: line.startIndex)..<separator.lowerBound])
            // The service's own line comes first; none of these keys is
            // printed twice at this depth.
            if values[key] == nil {
                values[key] = String(line[separator.upperBound...])
            }
        }
        guard let state = values["state"] else {
            throw LaunchRecordError.missing("state")
        }
        guard let printedRuns = values["runs"] else {
            throw LaunchRecordError.missing("runs")
        }
        guard let runs = Int(printedRuns), runs >= 0 else {
            throw LaunchRecordError.unreadable("runs = \(printedRuns)")
        }
        self.init(
            state: state,
            runs: runs,
            lastExit: values["last exit code"].map(LaunchLastExit.init(printed:)),
            jobState: values["job state"],
            properties: values["properties"]?.components(separatedBy: " | ") ?? []
        )
    }
}

extension LaunchLastExit {
    /// Reads the value of a `last exit code` line.
    init(printed: String) {
        if printed == "(never exited)" {
            self = .never
            return
        }
        // `78: EX_CONFIG`, or the bare code.
        let code = printed.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)[0]
        self = Int32(code).map(LaunchLastExit.code) ?? .other(printed)
    }
}

/// What a record says of the agent's start.
public enum LaunchCondition: Hashable, Sendable {
    /// launchd shows its program as running. It shows a start so for a
    /// moment before macOS refuses it, too.
    case running
    /// launchd has not started it since it was registered.
    case idle
    /// Its program started, and ended by itself.
    case exited(LaunchLastExit?)
    /// macOS refused its start under the launch constraint of the record it
    /// keeps, once: its next failed start has the record replaced.
    case refusedOnce
    /// macOS refused its start again and has replaced its record (exit code
    /// 78): launchd still holds the old one, and only a new registration
    /// finds the new.
    case recordReplaced
}

extension LaunchRecord {
    /// launchd's name for a start that never reached the program.
    static let spawnFailed = "spawn failed"
    /// The property launchd gives a job whose start the launch constraint
    /// refused.
    static let needsConstraintUpdate = "needs LWCR update"
    /// The exit code of a start that asked macOS for the new record.
    static let configurationExit: Int32 = 78

    /// What the record says of the agent's start, or `nil` for a state
    /// this build does not know, which `summary` names.
    public var condition: LaunchCondition? {
        if jobState == Self.spawnFailed {
            // The last start never reached the program: under the launch
            // constraint, or for a reason this build does not know.
            guard properties.contains(Self.needsConstraintUpdate) else {
                return nil
            }
            return lastExit == .code(Self.configurationExit) ? .recordReplaced : .refusedOnce
        }
        if state == "running" {
            return .running
        }
        if runs == 0 {
            return .idle
        }
        if jobState == "exited" {
            return .exited(lastExit)
        }
        return nil
    }

    /// The record's lines in one, as `launchctl print` names them, for the
    /// operator.
    public var summary: String {
        var parts = ["state = \(state)", "runs = \(runs)"]
        switch lastExit {
        case .never?: parts.append("last exit code = (never exited)")
        case .code(let code)?: parts.append("last exit code = \(code)")
        case .other(let text)?: parts.append("last exit code = \(text)")
        case nil: break
        }
        if let jobState {
            parts.append("job state = \(jobState)")
        }
        if !properties.isEmpty {
            parts.append("properties = \(properties.joined(separator: " | "))")
        }
        return parts.joined(separator: ", ")
    }
}

/// What launchd says of one agent when it is asked.
public enum LaunchReading: Hashable, Sendable {
    /// launchd does not list the agent.
    case notListed
    /// Its record is in a state this build does not know; the record's
    /// lines.
    case unknown(String)
    /// What its record says of its start.
    case condition(LaunchCondition)

    /// The reading of `record`; `nil` for an agent launchd does not list.
    public init(_ record: LaunchRecord?) {
        guard let record else {
            self = .notListed
            return
        }
        self = record.condition.map(LaunchReading.condition) ?? .unknown(record.summary)
    }
}
