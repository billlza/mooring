// SPDX-License-Identifier: GPL-3.0-or-later

// The open alerts of a deployment's status (`mooring-daemon-core`'s
// `alert::OpenAlert`, design §15.8): each with its severity, its condition,
// since when the condition holds and when it was raised. Conditions carry
// aggregates and node ids, never a user's id or alias.

import Foundation

/// An alert's severity.
public enum Severity: String, Decodable, Sendable, CaseIterable {
    case critical, warning
}

/// One of a node's engines.
public enum NodeEngine: String, Decodable, Sendable, CaseIterable {
    case xray, hy2

    /// The engine's unit name on the node.
    public var program: String {
        switch self {
        case .xray: "mooring-xray"
        case .hy2: "mooring-hy2"
        }
    }
}

/// Where an engine runs.
public enum EngineHost: Decodable, Hashable, Sendable {
    case mac(engine: MacEngine)
    case node(node: NodeId, engine: NodeEngine)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("mac", let value?):
            self = .mac(engine: try value.fields("engine").field(MacEngine.self, "engine"))
        case ("node", let value?):
            let object = try value.fields("node", "engine")
            self = .node(
                node: try object.field(NodeId.self, "node"),
                engine: try object.field(NodeEngine.self, "engine"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// The kind of a reason the exit is degraded, as an alert carries it.
public enum DegradedReasonKind: String, Decodable, Sendable, CaseIterable {
    case nodeProbeFailed = "NodeProbeFailed"
    case reachabilitySuspect = "ReachabilitySuspect"
    case watchStale = "WatchStale"
    case onBattery = "OnBattery"
    case powerHelperExited = "PowerHelperExited"
    case ownNetworksUnreadable = "OwnNetworksUnreadable"
}

/// The M7's critical thermal levels.
public enum CriticalThermalLevel: String, Decodable, Sendable, CaseIterable {
    case level2, level3
}

/// What an alert is about.
public enum AlertCondition: Decodable, Hashable, Sendable {
    // Critical.
    case exitViolation(violations: [ViolationKind])
    case simCapReached(cycleStart: CalendarDate)
    case routerOffloadActive
    case routerWifiRadioOn
    case routerOverheating(level: CriticalThermalLevel)
    case routerRestarted
    case nodeHalted(node: NodeId)
    case rollbackFailed(node: NodeId)
    case gateCloseFailed(node: NodeId)
    case engineCrashLoop(host: EngineHost)
    case hostKeyMismatch(node: NodeId)
    case macSilent(node: NodeId)
    case nodeUnreachable(node: NodeId, since: UnixTime)
    case nodeDiskLow(node: NodeId, freeBytes: UInt64)
    // Warnings.
    case simWarn(cycleStart: CalendarDate)
    case simForecastCrossing(cycleStart: CalendarDate, threshold: SimThreshold, on: CalendarDate)
    case exitDegraded(reasons: [DegradedReasonKind])
    case foreignNetworkAttached(findings: UInt64)
    case reachabilitySuspect(node: NodeId)
    case targetDegraded(node: NodeId)
    case routerNoService
    case routerOnLte
    case routerThermalStepDown
    /// RSRP in tenths of dBm.
    case routerWeakSignal(rsrpDbmX10: Int16)
    case routerFirmwareChanged
    case routerUnreadSms(count: UInt64)
    case routerCounterMismatch(permille: UInt32)
    case usersNearQuota(count: UInt64)
    case usersOverQuota(count: UInt64)
    case usersSuspended(count: UInt64)
    case usersExpiringSoon(count: UInt64)
    case usersExpired(count: UInt64)
    case capacitySaturated
    case exitFlowCapHit(node: NodeId, count: UInt64)
    case nodeClockUnsynced(node: NodeId)
    case nodeRebootPending(node: NodeId, since: UnixTime)
    case pendingApply(node: NodeId, since: UnixTime)
    case operatorHoldLong(node: NodeId, since: UnixTime)
    case accountingCanaryMissing(node: NodeId, inbounds: [Inbound])

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("exit_violation", let value?):
            self = .exitViolation(
                violations: try value.fields("violations").field([ViolationKind].self, "violations"))
        case ("sim_cap_reached", let value?):
            self = .simCapReached(cycleStart: try Self.cycleStart(value))
        case ("router_offload_active", nil): self = .routerOffloadActive
        case ("router_wifi_radio_on", nil): self = .routerWifiRadioOn
        case ("router_overheating", let value?):
            self = .routerOverheating(
                level: try value.fields("level").field(CriticalThermalLevel.self, "level"))
        case ("router_restarted", nil): self = .routerRestarted
        case ("node_halted", let value?): self = .nodeHalted(node: try Self.node(value))
        case ("rollback_failed", let value?): self = .rollbackFailed(node: try Self.node(value))
        case ("gate_close_failed", let value?): self = .gateCloseFailed(node: try Self.node(value))
        case ("engine_crash_loop", let value?):
            self = .engineCrashLoop(host: try value.fields("host").field(EngineHost.self, "host"))
        case ("host_key_mismatch", let value?): self = .hostKeyMismatch(node: try Self.node(value))
        case ("mac_silent", let value?): self = .macSilent(node: try Self.node(value))
        case ("node_unreachable", let value?):
            let (node, since) = try Self.nodeSince(value)
            self = .nodeUnreachable(node: node, since: since)
        case ("node_disk_low", let value?):
            let object = try value.fields("node", "free_bytes")
            self = .nodeDiskLow(
                node: try object.field(NodeId.self, "node"),
                freeBytes: try object.field(UInt64.self, "free_bytes"))
        case ("sim_warn", let value?):
            self = .simWarn(cycleStart: try Self.cycleStart(value))
        case ("sim_forecast_crossing", let value?):
            let object = try value.fields("cycle_start", "threshold", "on")
            self = .simForecastCrossing(
                cycleStart: try object.field(CalendarDate.self, "cycle_start"),
                threshold: try object.field(SimThreshold.self, "threshold"),
                on: try object.field(CalendarDate.self, "on"))
        case ("exit_degraded", let value?):
            self = .exitDegraded(
                reasons: try value.fields("reasons").field([DegradedReasonKind].self, "reasons"))
        case ("foreign_network_attached", let value?):
            self = .foreignNetworkAttached(
                findings: try value.fields("findings").field(UInt64.self, "findings"))
        case ("reachability_suspect", let value?):
            self = .reachabilitySuspect(node: try Self.node(value))
        case ("target_degraded", let value?): self = .targetDegraded(node: try Self.node(value))
        case ("router_no_service", nil): self = .routerNoService
        case ("router_on_lte", nil): self = .routerOnLte
        case ("router_thermal_step_down", nil): self = .routerThermalStepDown
        case ("router_weak_signal", let value?):
            self = .routerWeakSignal(
                rsrpDbmX10: try value.fields("rsrp_dbm_x10").field(Int16.self, "rsrp_dbm_x10"))
        case ("router_firmware_changed", nil): self = .routerFirmwareChanged
        case ("router_unread_sms", let value?):
            self = .routerUnreadSms(count: try Self.count(value))
        case ("router_counter_mismatch", let value?):
            self = .routerCounterMismatch(
                permille: try value.fields("permille").field(UInt32.self, "permille"))
        case ("users_near_quota", let value?): self = .usersNearQuota(count: try Self.count(value))
        case ("users_over_quota", let value?): self = .usersOverQuota(count: try Self.count(value))
        case ("users_suspended", let value?): self = .usersSuspended(count: try Self.count(value))
        case ("users_expiring_soon", let value?):
            self = .usersExpiringSoon(count: try Self.count(value))
        case ("users_expired", let value?): self = .usersExpired(count: try Self.count(value))
        case ("capacity_saturated", nil): self = .capacitySaturated
        case ("exit_flow_cap_hit", let value?):
            let object = try value.fields("node", "count")
            self = .exitFlowCapHit(
                node: try object.field(NodeId.self, "node"), count: try object.field(UInt64.self, "count"))
        case ("node_clock_unsynced", let value?): self = .nodeClockUnsynced(node: try Self.node(value))
        case ("node_reboot_pending", let value?):
            let (node, since) = try Self.nodeSince(value)
            self = .nodeRebootPending(node: node, since: since)
        case ("pending_apply", let value?):
            let (node, since) = try Self.nodeSince(value)
            self = .pendingApply(node: node, since: since)
        case ("operator_hold_long", let value?):
            let (node, since) = try Self.nodeSince(value)
            self = .operatorHoldLong(node: node, since: since)
        case ("accounting_canary_missing", let value?):
            let object = try value.fields("node", "inbounds")
            self = .accountingCanaryMissing(
                node: try object.field(NodeId.self, "node"),
                inbounds: try object.field([Inbound].self, "inbounds"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    private static func node(_ value: any Decoder) throws -> NodeId {
        try value.fields("node").field(NodeId.self, "node")
    }

    private static func count(_ value: any Decoder) throws -> UInt64 {
        try value.fields("count").field(UInt64.self, "count")
    }

    private static func cycleStart(_ value: any Decoder) throws -> CalendarDate {
        try value.fields("cycle_start").field(CalendarDate.self, "cycle_start")
    }

    private static func nodeSince(_ value: any Decoder) throws -> (NodeId, UnixTime) {
        let object = try value.fields("node", "since")
        return (try object.field(NodeId.self, "node"), try object.field(UnixTime.self, "since"))
    }
}

/// An open alert.
public struct OpenAlert: Decodable, Hashable, Sendable {
    public let severity: Severity
    public let condition: AlertCondition
    /// Since when the condition has been continuously active.
    public let activeSince: UnixTime
    /// When it was raised.
    public let raisedAt: UnixTime

    enum CodingKeys: String, CodingKey, CaseIterable {
        case severity, condition
        case activeSince = "active_since"
        case raisedAt = "raised_at"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        severity = try object.decode(Severity.self, forKey: .severity)
        condition = try object.decode(AlertCondition.self, forKey: .condition)
        activeSince = try object.decode(UnixTime.self, forKey: .activeSince)
        raisedAt = try object.decode(UnixTime.self, forKey: .raisedAt)
    }
}
