// SPDX-License-Identifier: GPL-3.0-or-later

// The nodes of a deployment's status (`mooring-daemon-core`'s
// `status::NodeRow`, design §15.2, §15.3): each node's role and stage, its
// generation against the deployment's, the latest in-chain probe through
// each protocol, and its agent as the Mac last saw it. A report mirrors
// the node's own `StatusV1` (`mooring-agent-proto`), whose enums keep their
// Rust names on the wire.

import Foundation

/// A node's role.
public enum NodeRole: String, Decodable, Sendable, CaseIterable {
    case primary, standby
}

/// A node's lifecycle stage.
public enum LifecycleStage: String, Decodable, Sendable, CaseIterable {
    case planned = "Planned"
    case adopted = "Adopted"
    case applied = "Applied"
    case retiring = "Retiring"
    case retiredPendingProviderDeletion = "RetiredPendingProviderDeletion"
    case retired = "Retired"
}

/// How an in-chain probe ended.
public enum InChainOutcome: Decodable, Hashable, Sendable {
    case verified
    /// A violation; the exit's latches carry the evidence.
    case violation(kind: ViolationKind)
    case failed(stage: ProbeStage)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("verified", nil): self = .verified
        case ("violation", let value?):
            self = .violation(kind: try value.fields("kind").field(ViolationKind.self, "kind"))
        case ("failed", let value?):
            self = .failed(stage: try value.fields("stage").field(ProbeStage.self, "stage"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// The latest in-chain probe through one protocol.
public struct InChainResult: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let outcome: InChainOutcome
    /// The round trip in milliseconds, when it completed.
    public let latencyMs: UInt32?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, outcome
        case latencyMs = "latency_ms"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        outcome = try object.decode(InChainOutcome.self, forKey: .outcome)
        latencyMs = try object.decodeNullable(UInt32.self, forKey: .latencyMs)
    }
}

/// The latest in-chain probes of a node.
public struct ProtocolVerdicts: Decodable, Hashable, Sendable {
    public let reality: InChainResult?
    public let hy2: InChainResult?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case reality, hy2
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        reality = try object.decodeNullable(InChainResult.self, forKey: .reality)
        hy2 = try object.decodeNullable(InChainResult.self, forKey: .hy2)
    }
}

/// Why a node's agent could not be polled.
public enum AgentUnreachable: String, Decodable, Sendable, CaseIterable {
    case spawn
    case hostKeyMismatch = "host_key_mismatch"
    case authFailed = "auth_failed"
    case transport, timeout
    case protocolMismatch = "protocol_mismatch"
    case decode
    case responseTooLarge = "response_too_large"
    case forcedCommandNotActive = "forced_command_not_active"
}

/// A node's gate.
public enum GateState: String, Decodable, Sendable, CaseIterable {
    case open = "Open"
    case closed = "Closed"
}

/// The drain hold: the Mac drained before it slept.
public struct MacDrainHold: Decodable, Hashable, Sendable {
    public let handshakeAtDrain: UnixTime?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case handshakeAtDrain = "handshake_at_drain"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        handshakeAtDrain = try object.decodeNullable(UnixTime.self, forKey: .handshakeAtDrain)
    }
}

/// The hold an egress violation set.
public struct EgressViolationHold: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let generation: UInt64

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, generation
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        generation = try object.decode(UInt64.self, forKey: .generation)
    }
}

/// The operator's hold.
public struct OperatorHold: Decodable, Hashable, Sendable {
    public let at: UnixTime

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
    }
}

/// The holds on a node's gate.
public struct Holds: Decodable, Hashable, Sendable {
    public let macDrain: MacDrainHold?
    public let egressViolation: EgressViolationHold?
    public let `operator`: OperatorHold?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case macDrain = "mac_drain"
        case egressViolation = "egress_violation"
        case `operator`
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        macDrain = try object.decodeNullable(MacDrainHold.self, forKey: .macDrain)
        egressViolation = try object.decodeNullable(EgressViolationHold.self, forKey: .egressViolation)
        `operator` = try object.decodeNullable(OperatorHold.self, forKey: .operator)
    }
}

/// Why a node halted.
public enum ShutdownReason: String, Decodable, Sendable, CaseIterable {
    case egressIsNodeAddress = "EgressIsNodeAddress"
    case `operator` = "Operator"
    case retire = "Retire"
}

/// A node's halt marker.
public struct Halt: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let reason: ShutdownReason

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, reason
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        reason = try object.decode(ShutdownReason.self, forKey: .reason)
    }
}

/// The last generation a node committed.
public struct AppliedGeneration: Decodable, Hashable, Sendable {
    public let generation: UInt64
    /// The SHA-256 of the configuration, in hex.
    public let digest: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case generation, digest
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        generation = try object.decode(UInt64.self, forKey: .generation)
        digest = try object.decode(String.self, forKey: .digest)
    }
}

/// An inbound a node serves.
public enum Inbound: String, Decodable, Sendable, CaseIterable {
    case reality = "Reality"
    case hy2 = "Hy2"
}

/// A condition a node's watch reports.
public enum WatchError: Decodable, Hashable, Sendable {
    case wgReadFailed
    case nftFailed
    case statsQueryFailed
    case targetDegraded
    case exitFlowCapHit(count: UInt64)
    case stateWrite(errno: Int32?)
    case macSilent(since: UnixTime?)
    case diskLow(free: UInt64)
    case clockUnsynced
    case rebootPending(since: UnixTime)
    case accountingCanaryMissing(inbounds: [Inbound])

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("WgReadFailed", nil): self = .wgReadFailed
        case ("NftFailed", nil): self = .nftFailed
        case ("StatsQueryFailed", nil): self = .statsQueryFailed
        case ("TargetDegraded", nil): self = .targetDegraded
        case ("ExitFlowCapHit", let value?):
            self = .exitFlowCapHit(count: try value.fields("count").field(UInt64.self, "count"))
        case ("StateWrite", let value?):
            self = .stateWrite(errno: try value.fields("errno").nullableField(Int32.self, "errno"))
        case ("MacSilent", let value?):
            self = .macSilent(since: try value.fields("since").nullableField(UnixTime.self, "since"))
        case ("DiskLow", let value?):
            self = .diskLow(free: try value.fields("free").field(UInt64.self, "free"))
        case ("ClockUnsynced", nil): self = .clockUnsynced
        case ("RebootPending", let value?):
            self = .rebootPending(since: try value.fields("since").field(UnixTime.self, "since"))
        case ("AccountingCanaryMissing", let value?):
            self = .accountingCanaryMissing(
                inbounds: try value.fields("inbounds").field([Inbound].self, "inbounds"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// Whether a node's engine runs.
public enum EngineRun: Decodable, Hashable, Sendable {
    case inactive
    case active(uptimeSecs: UInt64, goHeapBytes: UInt64?)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("Inactive", nil): self = .inactive
        case ("Active", let value?):
            let object = try value.fields("uptime_secs", "go_heap_bytes")
            self = .active(
                uptimeSecs: try object.field(UInt64.self, "uptime_secs"),
                goHeapBytes: try object.nullableField(UInt64.self, "go_heap_bytes"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// One of a node's engines.
public struct EngineState: Decodable, Hashable, Sendable {
    public let restarts: UInt32
    public let run: EngineRun

    enum CodingKeys: String, CodingKey, CaseIterable {
        case restarts, run
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        restarts = try object.decode(UInt32.self, forKey: .restarts)
        run = try object.decode(EngineRun.self, forKey: .run)
    }
}

/// A node's engines.
public struct EngineHealth: Decodable, Hashable, Sendable {
    public let xray: EngineState
    public let hy2: EngineState

    enum CodingKeys: String, CodingKey, CaseIterable {
        case xray, hy2
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        xray = try object.decode(EngineState.self, forKey: .xray)
        hy2 = try object.decode(EngineState.self, forKey: .hy2)
    }
}

/// A node's host.
public struct HostHealth: Decodable, Hashable, Sendable {
    public let uptimeSecs: UInt64
    /// The 1-minute load average, in thousandths.
    public let loadMilli: UInt32
    public let memAvailableBytes: UInt64
    public let diskFreeBytes: UInt64
    public let journalBytes: UInt64
    public let rebootRequired: Bool
    public let lastUnattendedUpgrade: UnixTime?
    public let ntpSynced: Bool

    enum CodingKeys: String, CodingKey, CaseIterable {
        case uptimeSecs = "uptime_secs"
        case loadMilli = "load_milli"
        case memAvailableBytes = "mem_available_bytes"
        case diskFreeBytes = "disk_free_bytes"
        case journalBytes = "journal_bytes"
        case rebootRequired = "reboot_required"
        case lastUnattendedUpgrade = "last_unattended_upgrade"
        case ntpSynced = "ntp_synced"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        uptimeSecs = try object.decode(UInt64.self, forKey: .uptimeSecs)
        loadMilli = try object.decode(UInt32.self, forKey: .loadMilli)
        memAvailableBytes = try object.decode(UInt64.self, forKey: .memAvailableBytes)
        diskFreeBytes = try object.decode(UInt64.self, forKey: .diskFreeBytes)
        journalBytes = try object.decode(UInt64.self, forKey: .journalBytes)
        rebootRequired = try object.decode(Bool.self, forKey: .rebootRequired)
        lastUnattendedUpgrade = try object.decodeNullable(UnixTime.self, forKey: .lastUnattendedUpgrade)
        ntpSynced = try object.decode(Bool.self, forKey: .ntpSynced)
    }
}

/// A node's uplink transfer this month, against the provider's allowance.
public struct UplinkTransfer: Decodable, Hashable, Sendable {
    /// The UTC month, `YYYY-MM`.
    public let month: String
    public let countedFrom: UnixTime
    public let rxBytes: UInt64
    public let txBytes: UInt64
    public let counterResets: UInt32

    enum CodingKeys: String, CodingKey, CaseIterable {
        case month
        case countedFrom = "counted_from"
        case rxBytes = "rx_bytes"
        case txBytes = "tx_bytes"
        case counterResets = "counter_resets"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        month = try object.decode(String.self, forKey: .month)
        countedFrom = try object.decode(UnixTime.self, forKey: .countedFrom)
        rxBytes = try object.decode(UInt64.self, forKey: .rxBytes)
        txBytes = try object.decode(UInt64.self, forKey: .txBytes)
        counterResets = try object.decode(UInt32.self, forKey: .counterResets)
    }
}

/// A node's latest status as the Mac received it. Its ages use the node's
/// clock only.
public struct NodeReport: Decodable, Hashable, Sendable {
    public let polledAt: UnixTime
    public let agentNow: UnixTime
    /// `nil` if the node's clock stepped back.
    public let watchAgeSecs: UInt64?
    public let gate: GateState
    public let holds: Holds
    public let halted: Halt?
    /// `nil` when no handshake has completed (or the clock stepped back).
    public let handshakeAgeSecs: UInt64?
    public let applied: AppliedGeneration?
    public let conditions: [WatchError]
    public let accountingAt: UnixTime?
    public let engines: EngineHealth
    public let host: HostHealth
    public let transfer: UplinkTransfer

    enum CodingKeys: String, CodingKey, CaseIterable {
        case polledAt = "polled_at"
        case agentNow = "agent_now"
        case watchAgeSecs = "watch_age_secs"
        case gate, holds, halted
        case handshakeAgeSecs = "handshake_age_secs"
        case applied, conditions
        case accountingAt = "accounting_at"
        case engines, host, transfer
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        polledAt = try object.decode(UnixTime.self, forKey: .polledAt)
        agentNow = try object.decode(UnixTime.self, forKey: .agentNow)
        watchAgeSecs = try object.decodeNullable(UInt64.self, forKey: .watchAgeSecs)
        gate = try object.decode(GateState.self, forKey: .gate)
        holds = try object.decode(Holds.self, forKey: .holds)
        halted = try object.decodeNullable(Halt.self, forKey: .halted)
        handshakeAgeSecs = try object.decodeNullable(UInt64.self, forKey: .handshakeAgeSecs)
        applied = try object.decodeNullable(AppliedGeneration.self, forKey: .applied)
        conditions = try object.decode([WatchError].self, forKey: .conditions)
        accountingAt = try object.decodeNullable(UnixTime.self, forKey: .accountingAt)
        engines = try object.decode(EngineHealth.self, forKey: .engines)
        host = try object.decode(HostHealth.self, forKey: .host)
        transfer = try object.decode(UplinkTransfer.self, forKey: .transfer)
    }
}

/// A node's agent as the Mac last saw it.
public enum NodeAgentState: Decodable, Hashable, Sendable {
    /// Not polled since the daemon started.
    case notPolled
    case reported(NodeReport)
    /// Polls have failed since `since`.
    case unreachable(since: UnixTime, cause: AgentUnreachable)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("not_polled", nil): self = .notPolled
        case ("reported", let value?):
            self = .reported(try NodeReport(from: value))
        case ("unreachable", let value?):
            let object = try value.fields("since", "cause")
            self = .unreachable(
                since: try object.field(UnixTime.self, "since"),
                cause: try object.field(AgentUnreachable.self, "cause"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// One node.
public struct NodeRow: Decodable, Hashable, Sendable {
    public let role: NodeRole
    public let stage: LifecycleStage
    /// The deployment's current configuration generation.
    public let currentGeneration: UInt64
    /// Since when the node has been behind the current generation.
    public let pendingApplySince: UnixTime?
    public let verdicts: ProtocolVerdicts
    public let agent: NodeAgentState

    enum CodingKeys: String, CodingKey, CaseIterable {
        case role, stage
        case currentGeneration = "current_generation"
        case pendingApplySince = "pending_apply_since"
        case verdicts, agent
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        role = try object.decode(NodeRole.self, forKey: .role)
        stage = try object.decode(LifecycleStage.self, forKey: .stage)
        currentGeneration = try object.decode(UInt64.self, forKey: .currentGeneration)
        pendingApplySince = try object.decodeNullable(UnixTime.self, forKey: .pendingApplySince)
        verdicts = try object.decode(ProtocolVerdicts.self, forKey: .verdicts)
        agent = try object.decode(NodeAgentState.self, forKey: .agent)
    }
}
