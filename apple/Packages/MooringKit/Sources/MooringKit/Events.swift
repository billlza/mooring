// SPDX-License-Identifier: GPL-3.0-or-later

// The event journals (`mooring-daemon-core`'s `events`, design §15.7): the
// document `mooringctl events --json` prints. The UTC days asked for, the
// entries of those days' files in the order of their times (the Mac's
// events, which the daemon derives from its statuses, and the lines it
// read from each node's journal), how many older entries the bound left
// out, and the files that ended in an incomplete line. The mirror keeps
// the Rust types' fields, closed enums and required `null`s. Like the
// journals, it names states, kinds, nodes and generations, never a user
// or an address.

import Foundation

/// The exit's phase as the Mac's journal keeps it: its state without the
/// egress address, the times and the details of its reasons.
public enum ExitPhase: Decodable, Hashable, Sendable {
    case disabled
    case preflight
    case starting
    case verifying
    case serving
    /// Serving, with problems of these kinds, each once, in the order the
    /// kinds are declared.
    case degraded(reasons: [DegradedReasonKind])
    case down(reason: DownReasonKind)
    case paused

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("disabled", nil): self = .disabled
        case ("preflight", nil): self = .preflight
        case ("starting", nil): self = .starting
        case ("verifying", nil): self = .verifying
        case ("serving", nil): self = .serving
        case ("degraded", let value?):
            self = .degraded(reasons: try value.fields("reasons").field([DegradedReasonKind].self, "reasons"))
        case ("down", let value?):
            self = .down(reason: try value.fields("reason").field(DownReasonKind.self, "reason"))
        case ("paused", nil): self = .paused
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

extension ExitState {
    /// The state's phase, as the Mac's journal keeps it (`ExitPhase::of`).
    public var phase: ExitPhase {
        switch self {
        case .disabled: .disabled
        case .preflight: .preflight
        case .starting: .starting
        case .verifying: .verifying
        case .serving: .serving
        case .degraded(let reasons):
            .degraded(reasons: DegradedReasonKind.allCases.filter { kind in reasons.contains { $0.kind == kind } })
        case .down(let reason): .down(reason: reason.kind)
        case .paused: .paused
        }
    }
}

/// What happened on the Mac.
public enum MacEventKind: Decodable, Hashable, Sendable {
    /// The daemon started with a deployment.
    case daemonStarted
    /// The power source changed, or the daemon learnt it at its start.
    case powerSource(PowerSource)
    /// The Mac went to sleep, after the exit drained.
    case slept(drain: DrainOutcome)
    /// The Mac woke.
    case woke
    /// The exit's phase changed, or the daemon's first status showed it.
    case exit(ExitPhase)
    /// A node's agent could not be polled, at the first failed poll of a
    /// run of failures, with the first failure's cause.
    case nodeUnreachable(node: NodeId, cause: AgentUnreachable)
    /// A node's agent answered a poll after polls had failed.
    case nodeReachable(node: NodeId)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("daemon_started", nil): self = .daemonStarted
        case ("power_source", let value?):
            self = .powerSource(try value.fields("source").field(PowerSource.self, "source"))
        case ("slept", let value?):
            self = .slept(drain: try value.fields("drain").field(DrainOutcome.self, "drain"))
        case ("woke", nil): self = .woke
        case ("exit", let value?):
            self = .exit(try value.fields("phase").field(ExitPhase.self, "phase"))
        case ("node_unreachable", let value?):
            let object = try value.fields("node", "cause")
            self = .nodeUnreachable(
                node: try object.field(NodeId.self, "node"),
                cause: try object.field(AgentUnreachable.self, "cause"))
        case ("node_reachable", let value?):
            self = .nodeReachable(node: try value.fields("node").field(NodeId.self, "node"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// An event of the Mac's journal: when it happened, by the Mac's clock,
/// and what happened.
public struct MacEvent: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let kind: MacEventKind

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, kind
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        kind = try object.decode(MacEventKind.self, forKey: .kind)
    }
}

/// A node's engine, by the user its unit runs as.
public enum EngineUser: String, Decodable, Sendable, CaseIterable {
    case xray = "Xray"
    case hy2 = "Hy2"

    /// The engine.
    public var engine: NodeEngine {
        switch self {
        case .xray: .xray
        case .hy2: .hy2
        }
    }
}

/// Why the Mac closes a node's gate with a hold.
public enum GateReason: String, Decodable, Sendable, CaseIterable {
    /// The Mac drained the node before it slept.
    case macDrain = "MacDrain"
    /// The Mac found an egress violation.
    case egressViolation = "EgressViolation"
    /// The operator closed the gate.
    case `operator` = "Operator"
}

/// The kind of a condition a node's watch reports, without its data.
public enum WatchErrorKind: String, Decodable, Sendable, CaseIterable {
    case wgReadFailed = "WgReadFailed"
    case nftFailed = "NftFailed"
    case statsQueryFailed = "StatsQueryFailed"
    case targetDegraded = "TargetDegraded"
    case targetReadFailed = "TargetReadFailed"
    case exitFlowCapHit = "ExitFlowCapHit"
    case stateWrite = "StateWrite"
    case macSilent = "MacSilent"
    case diskLow = "DiskLow"
    case clockUnsynced = "ClockUnsynced"
    case rebootPending = "RebootPending"
    case accountingCanaryMissing = "AccountingCanaryMissing"
}

/// What happened on a node.
public enum AgentEventKind: Decodable, Hashable, Sendable {
    /// The watch raised a condition, with its data when it was raised.
    case conditionRaised(WatchError)
    /// A condition the watch had raised no longer holds.
    case conditionCleared(WatchErrorKind)
    /// The watch opened the gate.
    case gateOpened
    /// The gate closed: the watch closed it, a hold was recorded, or the
    /// node was halted.
    case gateClosed
    /// A hold was recorded.
    case holdRecorded(GateReason)
    /// A hold was cleared.
    case holdCleared(GateReason)
    /// The node was halted.
    case halted(ShutdownReason)
    /// The node resumed; the engines run this generation.
    case resumed(generation: UInt64)
    /// A transaction was confirmed: this generation is current.
    case committed(generation: UInt64)
    /// An engine's unit was restarted by its `Restart=` policy.
    case engineRestarted(EngineUser)
    /// The host booted.
    case hostBooted

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("ConditionRaised", let value?):
            self = .conditionRaised(try value.fields("condition").field(WatchError.self, "condition"))
        case ("ConditionCleared", let value?):
            self = .conditionCleared(try value.fields("condition").field(WatchErrorKind.self, "condition"))
        case ("GateOpened", nil): self = .gateOpened
        case ("GateClosed", nil): self = .gateClosed
        case ("HoldRecorded", let value?):
            self = .holdRecorded(try value.fields("hold").field(GateReason.self, "hold"))
        case ("HoldCleared", let value?):
            self = .holdCleared(try value.fields("hold").field(GateReason.self, "hold"))
        case ("Halted", let value?):
            self = .halted(try value.fields("reason").field(ShutdownReason.self, "reason"))
        case ("Resumed", let value?):
            self = .resumed(generation: try value.fields("generation").field(UInt64.self, "generation"))
        case ("Committed", let value?):
            self = .committed(generation: try value.fields("generation").field(UInt64.self, "generation"))
        case ("EngineRestarted", let value?):
            self = .engineRestarted(try value.fields("engine").field(EngineUser.self, "engine"))
        case ("HostBooted", nil): self = .hostBooted
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// An event of a node's journal: its number there, the node's clock when
/// the agent recorded it, and what happened.
public struct AgentEvent: Decodable, Hashable, Sendable {
    public let seq: UInt64
    public let at: UnixTime
    public let kind: AgentEventKind

    enum CodingKeys: String, CodingKey, CaseIterable {
        case seq, at, kind
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        seq = try object.decode(UInt64.self, forKey: .seq)
        at = try object.decode(UnixTime.self, forKey: .at)
        kind = try object.decode(AgentEventKind.self, forKey: .kind)
    }
}

/// What a line of a node's copy holds.
public enum NodeEntry: Decodable, Hashable, Sendable {
    /// An event of the node's journal.
    case event(AgentEvent)
    /// The events numbered `from` up to (not including) `to` were pruned
    /// from the node's journal before the Mac read them; `to` is above
    /// `from`.
    case gap(from: UInt64, to: UInt64)
    /// The node's journal ended before the number the Mac asked from, so
    /// it was started anew; the Mac reads it again from its first number.
    /// `end` is the number its next event will get.
    case reset(end: UInt64)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.onlyKey()
        switch tag {
        case "event":
            self = .event(try AgentEvent(from: value))
        case "gap":
            let object = try value.fields("from", "to")
            let from = try object.field(UInt64.self, "from")
            let to = try object.field(UInt64.self, "to")
            // The one value rule the mirror repeats, as the Rust type's
            // decoding holds it: the screen names the last number missing,
            // the one before `to`.
            guard to > from else {
                throw DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: decoder.codingPath, debugDescription: "a gap from \(from) to \(to) is empty"))
            }
            self = .gap(from: from, to: to)
        case "reset":
            self = .reset(end: try value.fields("end").field(UInt64.self, "end"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// A line of a node's copy: when the Mac read it, by the Mac's clock, and
/// what it read.
public struct NodeLine: Decodable, Hashable, Sendable {
    public let readAt: UnixTime
    public let entry: NodeEntry

    enum CodingKeys: String, CodingKey, CaseIterable {
        case readAt = "read_at"
        case entry
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        readAt = try object.decode(UnixTime.self, forKey: .readAt)
        entry = try object.decode(NodeEntry.self, forKey: .entry)
    }

    /// When the line's entry happened: an event's own time (the node's
    /// clock), or the read's (the Mac's) for a gap or a reset.
    public var at: UnixTime {
        switch entry {
        case .event(let event): event.at
        case .gap, .reset: readAt
        }
    }
}

/// An entry of the document: an event of the Mac's journal, or a line of
/// a node's copy.
public enum JournalEntry: Decodable, Hashable, Sendable {
    case mac(MacEvent)
    case node(node: NodeId, line: NodeLine)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.onlyKey()
        switch tag {
        case "mac":
            self = .mac(try MacEvent(from: value))
        case "node":
            let object = try value.fields("node", "line")
            self = .node(node: try object.field(NodeId.self, "node"), line: try object.field(NodeLine.self, "line"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    /// When the entry happened.
    public var at: UnixTime {
        switch self {
        case .mac(let event): event.at
        case .node(_, let line): line.at
        }
    }
}

/// A day file that ended in an incomplete line: the Mac's (`node` is
/// `nil`) or a node's copy's.
public struct JournalDay: Decodable, Hashable, Sendable {
    public let node: NodeId?
    public let day: CalendarDate

    enum CodingKeys: String, CodingKey, CaseIterable {
        case node, day
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        node = try object.decodeNullable(NodeId.self, forKey: .node)
        day = try object.decode(CalendarDate.self, forKey: .day)
    }
}

/// The document: the UTC days asked for, the entries of those days' files
/// in the order of their times (the newest 5,000 of them), how many older
/// ones were left out, and the day files that ended in an incomplete line.
public struct EventsDocument: Decodable, Hashable, Sendable {
    /// The version this build reads.
    public static let version: UInt32 = 1

    public let since: CalendarDate
    public let until: CalendarDate
    public let entries: [JournalEntry]
    public let omitted: UInt64
    public let incompleteDays: [JournalDay]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, since, until, entries, omitted
        case incompleteDays = "incomplete_days"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        let version = try object.decode(UInt32.self, forKey: .version)
        guard version == Self.version else {
            throw ConsoleDecodingError.unsupportedVersion(version)
        }
        since = try object.decode(CalendarDate.self, forKey: .since)
        until = try object.decode(CalendarDate.self, forKey: .until)
        entries = try object.decode([JournalEntry].self, forKey: .entries)
        omitted = try object.decode(UInt64.self, forKey: .omitted)
        incompleteDays = try object.decode([JournalDay].self, forKey: .incompleteDays)
    }

    /// The one line `events --json` prints, with or without its newline.
    public static func decode(line: some DataProtocol) throws -> EventsDocument {
        try JSONDecoder().decode(EventsDocument.self, from: Data(line))
    }

    /// The entries by the day of their time in `calendar`: the newest day
    /// first, and in each day the newest entry first (entries of one time
    /// in the reverse of the document's order).
    public func days(in calendar: Calendar) -> [EventDay] {
        var days: [EventDay] = []
        for entry in entries.reversed() {
            let start = calendar.startOfDay(for: entry.at.date)
            if let last = days.indices.last, days[last].start == start {
                days[last].entries.append(entry)
            } else {
                days.append(EventDay(start: start, entries: [entry]))
            }
        }
        return days
    }
}

extension EventsDocument: CommandDocument {
    /// The document of the CLI's default range, the last seven days.
    public static let arguments = ["events", "--json"]

    /// At most 5,000 entries, each a journal line of under 500 bytes
    /// (`daemon-core` pins its longest lines) with its node's name: under
    /// 2.7 MB with the days listed after them; 4 MiB leaves room.
    public static let outputLimit = 4 << 20
}

/// The entries of one day in a calendar, the newest first.
public struct EventDay: Hashable, Sendable {
    /// The day's start in the calendar.
    public let start: Date
    public fileprivate(set) var entries: [JournalEntry]
}
