// SPDX-License-Identifier: GPL-3.0-or-later

// The exit Mac's section of a deployment's status (`mooring-daemon-core`'s
// `status::ExitSection`, design §10, §15.2): the exit's state and why, the
// latched violations with their evidence, the egress, the latest carrier
// check, the two engines, the Mac's power and the foreign networks found.

import Foundation

/// Where a probe failed.
public enum ProbeStage: String, Decodable, Sendable, CaseIterable {
    case connect, read, parse
    case proberUnavailable = "prober_unavailable"
    case carrierAddressUnstable = "carrier_address_unstable"
}

/// A protocol a node serves, which the Mac probes through.
public enum ProbeProtocol: String, Decodable, Sendable, CaseIterable {
    case reality, hy2
}

/// One of the Mac's two engines.
public enum MacEngine: String, Decodable, Sendable, CaseIterable {
    case exit, probe

    /// The engine's process name.
    public var program: String {
        switch self {
        case .exit: "mooring-exit"
        case .probe: "mooring-probe"
        }
    }
}

/// A violation of the egress rules, with its evidence (`mooring-model`'s
/// `verdict::Violation`, design §10.2).
public enum Violation: Decodable, Hashable, Sendable {
    /// The egress address is one of a node's own.
    case egressIsNodeAddress(node: NodeId, ip: String)
    /// The egress address is outside the recorded carrier prefixes.
    case outsideCarrierPrefixes(ip: String)
    /// The egress address is the separate uplink's.
    case egressEqualsUplink(ip: String)
    /// The bracketing direct probes `d1`, `d2` agreed on an address the
    /// in-chain probe did not observe.
    case egressMismatch(d1: String, d2: String, observed: String)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("egress_is_node_address", let value?):
            let object = try value.fields("node", "ip")
            self = .egressIsNodeAddress(
                node: try object.field(NodeId.self, "node"), ip: try object.field(String.self, "ip"))
        case ("outside_carrier_prefixes", let value?):
            self = .outsideCarrierPrefixes(ip: try value.fields("ip").field(String.self, "ip"))
        case ("egress_equals_uplink", let value?):
            self = .egressEqualsUplink(ip: try value.fields("ip").field(String.self, "ip"))
        case ("egress_mismatch", let value?):
            let object = try value.fields("d1", "d2", "observed")
            self = .egressMismatch(
                d1: try object.field(String.self, "d1"),
                d2: try object.field(String.self, "d2"),
                observed: try object.field(String.self, "observed"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    /// The violation's kind.
    public var kind: ViolationKind {
        switch self {
        case .egressIsNodeAddress: .egressIsNodeAddress
        case .outsideCarrierPrefixes: .outsideCarrierPrefixes
        case .egressEqualsUplink: .egressEqualsUplink
        case .egressMismatch: .egressMismatch
        }
    }
}

/// A violation's kind, as alerts and in-chain verdicts carry it.
public enum ViolationKind: String, Decodable, Sendable, CaseIterable {
    case egressIsNodeAddress = "EgressIsNodeAddress"
    case outsideCarrierPrefixes = "OutsideCarrierPrefixes"
    case egressEqualsUplink = "EgressEqualsUplink"
    case egressMismatch = "EgressMismatch"
}

/// A network the Mac must not be attached to while the exit runs (design
/// §10.2, P0-2).
public enum ForeignNetworkFinding: Decodable, Hashable, Sendable {
    case routableIpv4(interface: String)
    case globalIpv6(interface: String)
    case defaultRoute(interface: String, family: IpFamily)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("routable_ipv4", let value?):
            self = .routableIpv4(interface: try value.fields("interface").field(String.self, "interface"))
        case ("global_ipv6", let value?):
            self = .globalIpv6(interface: try value.fields("interface").field(String.self, "interface"))
        case ("default_route", let value?):
            let object = try value.fields("interface", "family")
            self = .defaultRoute(
                interface: try object.field(String.self, "interface"),
                family: try object.field(IpFamily.self, "family"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    /// The interface found.
    public var interface: String {
        switch self {
        case .routableIpv4(let interface), .globalIpv6(let interface),
            .defaultRoute(let interface, _):
            interface
        }
    }
}

/// What kind of connection a declared own network is (design §10.2, P0-2).
public enum OwnNetworkKind: String, Decodable, Sendable, CaseIterable {
    case personalHotspot = "personal_hotspot"
    case broadband
}

/// An attachment the network check allowed: a network the operator declared
/// as their own, or a TUN numbered only in the benchmarking range (CFM's).
public enum AllowedNetwork: Decodable, Hashable, Sendable {
    case own(interface: String, kind: OwnNetworkKind)
    case benchmarkingTun(interface: String)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("own", let value?):
            let object = try value.fields("interface", "kind")
            self = .own(
                interface: try object.field(String.self, "interface"),
                kind: try object.field(OwnNetworkKind.self, "kind"))
        case ("benchmarking_tun", let value?):
            self = .benchmarkingTun(
                interface: try value.fields("interface").field(String.self, "interface"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    /// The interface allowed.
    public var interface: String {
        switch self {
        case .own(let interface, _), .benchmarkingTun(let interface):
            interface
        }
    }
}

/// An input of the own-network match that could not be read; no declared
/// network matches until it can.
public enum OwnNetworkInput: String, Decodable, Sendable, CaseIterable {
    case declarations
    case routerIdentities = "router_identities"
}

/// An IP family.
public enum IpFamily: String, Decodable, Sendable, CaseIterable {
    case v4, v6
}

/// Why the exit is degraded: it serves, with a problem.
public enum DegradedReason: Decodable, Hashable, Sendable {
    /// A node's probe failed; the exit keeps serving its other nodes.
    case nodeProbeFailed(node: NodeId, protocol: ProbeProtocol, stage: ProbeStage)
    /// A node may be blocked in China.
    case reachabilitySuspect(node: NodeId)
    /// A node's watch status is older than 30 s.
    case watchStale(node: NodeId)
    /// The Mac runs on battery and may sleep.
    case onBattery
    /// The power helper exited.
    case powerHelperExited
    /// The own-network declarations or configd's services could not be
    /// read, so no declared network matches.
    case ownNetworksUnreadable(input: OwnNetworkInput)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("node_probe_failed", let value?):
            let object = try value.fields("node", "protocol", "stage")
            self = .nodeProbeFailed(
                node: try object.field(NodeId.self, "node"),
                protocol: try object.field(ProbeProtocol.self, "protocol"),
                stage: try object.field(ProbeStage.self, "stage"))
        case ("reachability_suspect", let value?):
            self = .reachabilitySuspect(node: try value.fields("node").field(NodeId.self, "node"))
        case ("watch_stale", let value?):
            self = .watchStale(node: try value.fields("node").field(NodeId.self, "node"))
        case ("on_battery", nil):
            self = .onBattery
        case ("power_helper_exited", nil):
            self = .powerHelperExited
        case ("own_networks_unreadable", let value?):
            self = .ownNetworksUnreadable(
                input: try value.fields("input").field(OwnNetworkInput.self, "input"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// Why the exit is down: its engine is stopped.
public enum DownReason: Decodable, Hashable, Sendable {
    case egressInterfaceAbsent
    case egressAmbiguous(matches: UInt32)
    case egressNoIpv4(interface: String)
    case egressSubnetMismatch
    case uplinkAbsent
    case uplinkEqualsEgress
    case noAppliedNode
    case directProbeFailed(node: NodeId, stage: ProbeStage)
    case carrierCheckUnrecorded
    case simPlanUnrecorded
    case secretsUnavailable
    case agentNotEnabled(node: NodeId)
    case engineSpawnFailed(engine: MacEngine)
    case engineConfigRejected(engine: MacEngine)
    case engineStartFailed(engine: MacEngine)
    case engineCrashLoop(engine: MacEngine)
    case violation(Violation)
    case simCapReached(cycleStart: CalendarDate)
    case foreignNetworkAttached(findings: [ForeignNetworkFinding])

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("egress_interface_absent", nil): self = .egressInterfaceAbsent
        case ("egress_ambiguous", let value?):
            self = .egressAmbiguous(matches: try value.fields("matches").field(UInt32.self, "matches"))
        case ("egress_no_ipv4", let value?):
            self = .egressNoIpv4(interface: try value.fields("interface").field(String.self, "interface"))
        case ("egress_subnet_mismatch", nil): self = .egressSubnetMismatch
        case ("uplink_absent", nil): self = .uplinkAbsent
        case ("uplink_equals_egress", nil): self = .uplinkEqualsEgress
        case ("no_applied_node", nil): self = .noAppliedNode
        case ("direct_probe_failed", let value?):
            let object = try value.fields("node", "stage")
            self = .directProbeFailed(
                node: try object.field(NodeId.self, "node"),
                stage: try object.field(ProbeStage.self, "stage"))
        case ("carrier_check_unrecorded", nil): self = .carrierCheckUnrecorded
        case ("sim_plan_unrecorded", nil): self = .simPlanUnrecorded
        case ("secrets_unavailable", nil): self = .secretsUnavailable
        case ("agent_not_enabled", let value?):
            self = .agentNotEnabled(node: try value.fields("node").field(NodeId.self, "node"))
        case ("engine_spawn_failed", let value?):
            self = .engineSpawnFailed(engine: try value.fields("engine").field(MacEngine.self, "engine"))
        case ("engine_config_rejected", let value?):
            self = .engineConfigRejected(engine: try value.fields("engine").field(MacEngine.self, "engine"))
        case ("engine_start_failed", let value?):
            self = .engineStartFailed(engine: try value.fields("engine").field(MacEngine.self, "engine"))
        case ("engine_crash_loop", let value?):
            self = .engineCrashLoop(engine: try value.fields("engine").field(MacEngine.self, "engine"))
        case ("violation", let value?):
            self = .violation(try Violation(from: value))
        case ("sim_cap_reached", let value?):
            self = .simCapReached(
                cycleStart: try value.fields("cycle_start").field(CalendarDate.self, "cycle_start"))
        case ("foreign_network_attached", let value?):
            self = .foreignNetworkAttached(
                findings: try value.fields("findings").field([ForeignNetworkFinding].self, "findings"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// The exit's state (design §10.1).
public enum ExitState: Decodable, Hashable, Sendable {
    /// The operator disabled the exit.
    case disabled
    /// Preflight is running.
    case preflight
    /// The engine is starting.
    case starting
    /// The engine runs and the first verdicts are pending.
    case verifying
    /// Serving through the verified carrier address `ip`.
    case serving(ip: String, verifiedAt: UnixTime)
    /// Serving, with problems.
    case degraded(reasons: [DegradedReason])
    /// Not serving.
    case down(reason: DownReason)
    /// The Mac is asleep; the exit drained before it slept.
    case paused

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("disabled", nil): self = .disabled
        case ("preflight", nil): self = .preflight
        case ("starting", nil): self = .starting
        case ("verifying", nil): self = .verifying
        case ("serving", let value?):
            let object = try value.fields("ip", "verified_at")
            self = .serving(
                ip: try object.field(String.self, "ip"),
                verifiedAt: try object.field(UnixTime.self, "verified_at"))
        case ("degraded", let value?):
            self = .degraded(reasons: try value.fields("reasons").field([DegradedReason].self, "reasons"))
        case ("down", let value?):
            self = .down(reason: try value.fields("reason").field(DownReason.self, "reason"))
        case ("paused", nil): self = .paused
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// A latched violation (`run/latch.json`).
public struct Latch: Decodable, Hashable, Sendable {
    public let violation: Violation
    public let at: UnixTime

    enum CodingKeys: String, CodingKey, CaseIterable {
        case violation, at
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        violation = try object.decode(Violation.self, forKey: .violation)
        at = try object.decode(UnixTime.self, forKey: .at)
    }
}

/// The egress link's state.
public struct LinkState: Decodable, Hashable, Sendable {
    public let up: Bool
    /// The negotiated speed in Mbit/s, when the driver reports one.
    public let speedMbps: UInt32?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case up
        case speedMbps = "speed_mbps"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        up = try object.decode(Bool.self, forKey: .up)
        speedMbps = try object.decodeNullable(UInt32.self, forKey: .speedMbps)
    }
}

/// The resolved egress interface.
public struct EgressFacts: Decodable, Hashable, Sendable {
    public let interface: String
    public let lladdr: String
    /// Its IPv4 address on the M7's network.
    public let ipv4: String
    public let link: LinkState

    enum CodingKeys: String, CodingKey, CaseIterable {
        case interface, lladdr, ipv4, link
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        interface = try object.decode(String.self, forKey: .interface)
        lladdr = try object.decode(String.self, forKey: .lladdr)
        ipv4 = try object.decode(String.self, forKey: .ipv4)
        link = try object.decode(LinkState.self, forKey: .link)
    }
}

/// How the egress's probes pair (design §10.2).
public enum Pairing: String, Decodable, Sendable, CaseIterable {
    case paired, unpaired
}

/// The latest direct probe's carrier check.
public struct CarrierCheck: Decodable, Hashable, Sendable {
    /// The carrier address the reflector saw.
    public let egressIp: String
    public let inCarrierPrefixes: Bool
    public let pairing: Pairing
    public let checkedAt: UnixTime

    enum CodingKeys: String, CodingKey, CaseIterable {
        case egressIp = "egress_ip"
        case inCarrierPrefixes = "in_carrier_prefixes"
        case pairing
        case checkedAt = "checked_at"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        egressIp = try object.decode(String.self, forKey: .egressIp)
        inCarrierPrefixes = try object.decode(Bool.self, forKey: .inCarrierPrefixes)
        pairing = try object.decode(Pairing.self, forKey: .pairing)
        checkedAt = try object.decode(UnixTime.self, forKey: .checkedAt)
    }
}

/// How a process last ended.
public enum ProcessEnd: Decodable, Hashable, Sendable {
    case exited(code: Int32)
    case signalled(signal: Int32)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("exited", let value?):
            self = .exited(code: try value.fields("code").field(Int32.self, "code"))
        case ("signalled", let value?):
            self = .signalled(signal: try value.fields("signal").field(Int32.self, "signal"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// An engine's last end.
public struct EngineExit: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let end: ProcessEnd

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, end
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        end = try object.decode(ProcessEnd.self, forKey: .end)
    }
}

/// One supervised engine on the Mac.
public struct EngineProcess: Decodable, Hashable, Sendable {
    /// Its process id while it runs.
    public let pid: UInt32?
    /// Restarts since the daemon started.
    public let restarts: UInt32
    public let lastExit: EngineExit?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case pid, restarts
        case lastExit = "last_exit"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        pid = try object.decodeNullable(UInt32.self, forKey: .pid)
        restarts = try object.decode(UInt32.self, forKey: .restarts)
        lastExit = try object.decodeNullable(EngineExit.self, forKey: .lastExit)
    }
}

/// Both engines on the Mac.
public struct MacEngines: Decodable, Hashable, Sendable {
    public let exit: EngineProcess
    public let probe: EngineProcess

    enum CodingKeys: String, CodingKey, CaseIterable {
        case exit, probe
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        exit = try object.decode(EngineProcess.self, forKey: .exit)
        probe = try object.decode(EngineProcess.self, forKey: .probe)
    }
}

/// Where the Mac's power comes from.
public enum PowerSource: String, Decodable, Sendable, CaseIterable {
    case ac, battery
}

/// How a sleep drain ended (design §10.3).
public enum DrainOutcome: String, Decodable, Sendable, CaseIterable {
    case completed
    case timedOut = "timed_out"
    case failed
}

/// The last sleep drain.
public struct DrainRecord: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let outcome: DrainOutcome

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, outcome
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        outcome = try object.decode(DrainOutcome.self, forKey: .outcome)
    }
}

/// The Mac's power (design §10.3).
public struct PowerStatus: Decodable, Hashable, Sendable {
    public let source: PowerSource
    /// Whether the power helper holds its assertions.
    public let assertionsHeld: Bool
    public let lastSleep: UnixTime?
    public let lastWake: UnixTime?
    public let lastDrain: DrainRecord?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case source
        case assertionsHeld = "assertions_held"
        case lastSleep = "last_sleep"
        case lastWake = "last_wake"
        case lastDrain = "last_drain"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        source = try object.decode(PowerSource.self, forKey: .source)
        assertionsHeld = try object.decode(Bool.self, forKey: .assertionsHeld)
        lastSleep = try object.decodeNullable(UnixTime.self, forKey: .lastSleep)
        lastWake = try object.decodeNullable(UnixTime.self, forKey: .lastWake)
        lastDrain = try object.decodeNullable(DrainRecord.self, forKey: .lastDrain)
    }
}

/// The exit Mac.
public struct ExitSection: Decodable, Hashable, Sendable {
    public let state: ExitState
    public let since: UnixTime
    public let latches: [Latch]
    /// The resolved egress; `nil` while it does not resolve.
    public let egress: EgressFacts?
    /// The latest carrier check; `nil` before the first direct probe.
    public let carrierCheck: CarrierCheck?
    public let engines: MacEngines
    public let power: PowerStatus
    /// Networks the Mac must not be attached to.
    public let foreignNetworks: [ForeignNetworkFinding]
    /// Attachments the check allowed: CFM's TUN and the operator's own
    /// networks.
    public let allowedNetworks: [AllowedNetwork]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case state, since, latches, egress
        case carrierCheck = "carrier_check"
        case engines, power
        case foreignNetworks = "foreign_networks"
        case allowedNetworks = "allowed_networks"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        state = try object.decode(ExitState.self, forKey: .state)
        since = try object.decode(UnixTime.self, forKey: .since)
        latches = try object.decode([Latch].self, forKey: .latches)
        egress = try object.decodeNullable(EgressFacts.self, forKey: .egress)
        carrierCheck = try object.decodeNullable(CarrierCheck.self, forKey: .carrierCheck)
        engines = try object.decode(MacEngines.self, forKey: .engines)
        power = try object.decode(PowerStatus.self, forKey: .power)
        foreignNetworks = try object.decode([ForeignNetworkFinding].self, forKey: .foreignNetworks)
        allowedNetworks = try object.decode([AllowedNetwork].self, forKey: .allowedNetworks)
    }
}
