// SPDX-License-Identifier: GPL-3.0-or-later

// `contract/status-fixtures/variants.json` holds one value of every variant
// of every enum a status carries, and one filled value of each record no
// scenario fills: a plan's line of each kind, and a node the operator
// halted after every hold had closed its gate. Each Swift enum has exactly
// as many cases as the Rust one has variants, so a variant added on either
// side fails a test; and every object of the fixture is read as strictly
// as the scenarios' are.

import Foundation
import Testing

@testable import MooringKit

/// A list of the fixture that holds objects (the values of an enum with
/// fields, or of a record), and the Swift type that reads it.
struct ListWithObjects: Sendable, CustomTestStringConvertible {
    let key: String
    /// How many values the list holds, each different.
    let count: Int
    /// Reads the list: how many values it holds, and how many differ.
    let read: @Sendable (Data) throws -> (values: Int, different: Int)

    init<T: Decodable & Hashable & Sendable>(_ type: T.Type, _ key: String, count: Int) {
        self.key = key
        self.count = count
        read = { data in
            let values = try JSONDecoder().decode([T].self, from: data)
            return (values.count, Set(values).count)
        }
    }

    var testDescription: String { key }
}

@Suite struct VariantsTests {
    /// Every list of the fixture that holds an object.
    static let listsWithObjects = [
        ListWithObjects(ExitState.self, "exit_state", count: 8),
        ListWithObjects(DegradedReason.self, "degraded_reason", count: 6),
        ListWithObjects(DownReason.self, "down_reason", count: 19),
        ListWithObjects(ProcessEnd.self, "process_end", count: 2),
        ListWithObjects(ForecastView.self, "forecast_view", count: 2),
        ListWithObjects(UsageView.self, "usage_view", count: 3),
        ListWithObjects(InChainOutcome.self, "in_chain_outcome", count: 3),
        ListWithObjects(NodeAgentState.self, "node_agent_state", count: 3),
        ListWithObjects(AlertCondition.self, "alert_condition", count: 40),
        ListWithObjects(EngineHost.self, "engine_host", count: 2),
        ListWithObjects(Crossing.self, "crossing", count: 3),
        ListWithObjects(UplinkUse.self, "uplink_use", count: 2),
        ListWithObjects(Saturation.self, "saturation", count: 4),
        ListWithObjects(ForeignNetworkFinding.self, "foreign_network_finding", count: 3),
        ListWithObjects(AllowedNetwork.self, "allowed_network", count: 2),
        ListWithObjects(QuotaState.self, "quota_state", count: 5),
        ListWithObjects(ExpiryState.self, "expiry_state", count: 3),
        ListWithObjects(UserStatus.self, "user_status", count: 4),
        ListWithObjects(SuspendReason.self, "suspend_reason", count: 4),
        ListWithObjects(Violation.self, "violation", count: 4),
        ListWithObjects(StopPolicy.self, "stop_policy", count: 2),
        ListWithObjects(WatchError.self, "watch_error", count: 12),
        ListWithObjects(EngineRun.self, "engine_run", count: 2),
        ListWithObjects(RouterReading.self, "router_reading", count: 2),
        ListWithObjects(RadioState.self, "radio_state", count: 2),
        ListWithObjects(PlanLine.self, "plan_line", count: 2),
    ]

    private static func document() throws -> [String: Any] {
        let document = try Fixtures.json(try Fixtures.data("contract/status-fixtures/variants.json"))
        return try #require(document as? [String: Any], "the fixture is not an object")
    }

    private func list(_ key: String) throws -> [Any] {
        try #require(try Self.document()[key] as? [Any], "the fixture has no list \(key)")
    }

    private func decode<T: Decodable>(_ type: T.Type, _ key: String) throws -> [T] {
        try JSONDecoder().decode([T].self, from: try Fixtures.encode(try list(key)))
    }

    @Test func everyRouterEnumVariantIsRead() throws {
        #expect(try decode(NetworkService.self, "network_service") == NetworkService.allCases)
        #expect(try decode(DataService.self, "data_service") == DataService.allCases)
        #expect(try decode(ThermalState.self, "thermal_state") == ThermalState.allCases)
        #expect(try decode(PowerState.self, "power_state") == PowerState.allCases)
        #expect(try decode(BatteryState.self, "battery_state") == BatteryState.allCases)
        #expect(try decode(ChargeSource.self, "charge_source") == ChargeSource.allCases)
        #expect(try decode(WifiApStatus.self, "wifi_ap_status") == WifiApStatus.allCases)
        #expect(try decode(LteBandwidth.self, "lte_bandwidth") == LteBandwidth.allCases)
        #expect(
            try decode(RouterUnavailableReason.self, "router_unavailable_reason")
                == RouterUnavailableReason.allCases)
        #expect(try decode(RouterAdvisory.self, "router_advisory") == RouterAdvisory.allCases)
    }

    @Test func everyRouterReadingRadioStateAndBandIsRead() throws {
        let readings = try decode(RouterReading.self, "router_reading")
        try #require(readings.count == 2, "\(readings)")
        guard case .available = readings[0], case .unavailable(.identityMismatch, nil) = readings[1]
        else {
            Issue.record("unexpected readings \(readings)")
            return
        }
        let radios = try decode(RadioState.self, "radio_state")
        try #require(radios.count == 2, "\(radios)")
        #expect(radios[0] == .noService)
        let bands = try decode(Band.self, "band")
        #expect(bands == [.lte(3), .nr(78)])
    }

    /// Every closed enum of a deployment's status, read from the fixture's
    /// list for it: exactly the Swift cases, in order.
    @Test func everyDeploymentEnumVariantIsRead() throws {
        #expect(try decode(ProbeStage.self, "probe_stage") == ProbeStage.allCases)
        #expect(try decode(PowerSource.self, "power_source") == PowerSource.allCases)
        #expect(try decode(DrainOutcome.self, "drain_outcome") == DrainOutcome.allCases)
        #expect(try decode(MeterAccuracy.self, "meter_accuracy") == MeterAccuracy.allCases)
        #expect(try decode(BaselineOrigin.self, "baseline_origin") == BaselineOrigin.allCases)
        #expect(try decode(AgentUnreachable.self, "agent_unreachable") == AgentUnreachable.allCases)
        #expect(try decode(Severity.self, "severity") == Severity.allCases)
        #expect(try decode(MacEngine.self, "mac_engine") == MacEngine.allCases)
        #expect(try decode(NodeEngine.self, "node_engine") == NodeEngine.allCases)
        #expect(
            try decode(DegradedReasonKind.self, "degraded_reason_kind") == DegradedReasonKind.allCases)
        #expect(
            try decode(CriticalThermalLevel.self, "critical_thermal_level")
                == CriticalThermalLevel.allCases)
        #expect(try decode(SimThreshold.self, "sim_threshold") == SimThreshold.allCases)
        #expect(try decode(IpFamily.self, "ip_family") == IpFamily.allCases)
        #expect(try decode(OwnNetworkKind.self, "own_network_kind") == OwnNetworkKind.allCases)
        #expect(try decode(OwnNetworkInput.self, "own_network_input") == OwnNetworkInput.allCases)
        #expect(try decode(ActiveNow.self, "active_now") == ActiveNow.allCases)
        #expect(
            try decode(ForecastErrorKind.self, "forecast_error_kind") == ForecastErrorKind.allCases)
        #expect(try decode(UsageErrorKind.self, "usage_error_kind") == UsageErrorKind.allCases)
        #expect(try decode(LifecycleStage.self, "lifecycle_stage") == LifecycleStage.allCases)
        #expect(try decode(NodeRole.self, "node_role") == NodeRole.allCases)
        #expect(try decode(Pairing.self, "pairing") == Pairing.allCases)
        #expect(try decode(ProbeProtocol.self, "probe_protocol") == ProbeProtocol.allCases)
        #expect(try decode(ViolationKind.self, "violation_kind") == ViolationKind.allCases)
        #expect(try decode(GateState.self, "gate_state") == GateState.allCases)
        #expect(try decode(ShutdownReason.self, "shutdown_reason") == ShutdownReason.allCases)
        #expect(try decode(Inbound.self, "inbound") == Inbound.allCases)
    }

    /// Every list that holds objects reads as one different value of each
    /// variant (or each value the builder gave a record), as many as the
    /// Swift enum has cases. A variant the Rust side adds is a value the
    /// mirror refuses.
    @Test(arguments: Self.listsWithObjects)
    func everyListWithObjectsReadsAsDifferentValues(_ list: ListWithObjects) throws {
        let read = try list.read(try Fixtures.encode(try self.list(list.key)))
        #expect(read.values == list.count)
        #expect(read.different == list.count)
    }

    /// Every object of every list refuses an unknown key, and every key of
    /// every object is required, a `null` too: the strict decoding of each
    /// variant with fields and each record, which the scenarios reach only
    /// in part.
    @Test(arguments: Self.listsWithObjects)
    func everyObjectIsReadStrictly(_ list: ListWithObjects) throws {
        let json = try self.list(list.key)
        let read = { (data: Data) throws in _ = try list.read(data) }
        let objects = try JSONPaths.expectEveryObjectRefusesAnUnknownKey(in: json, decode: read)
        try JSONPaths.expectEveryKeyIsRequired(in: json, decode: read)
        #expect(objects > 0)
    }

    /// The table above names every list of the fixture that holds an
    /// object, so a list the Rust side adds is read strictly too.
    @Test func theTableNamesEveryListWithObjects() throws {
        let withObjects = try Self.document().filter { !JSONPaths.objects(in: $0.value).isEmpty }.keys
        let listed = Set(Self.listsWithObjects.map(\.key))
        #expect(listed.count == Self.listsWithObjects.count)
        #expect(Set(withObjects) == listed)
    }

    /// The usage view's third value, the bare `not_pulled` string, reads as
    /// its own case rather than as unavailable.
    @Test func theUsageViewReadsNotPulledAsItsOwnCase() throws {
        #expect(try decode(UsageView.self, "usage_view").last == .notPulled)
    }

    /// Each watch condition reads as its own case with its data: a target
    /// check's result the watch cannot read keeps its errno, and reads as
    /// neither a failed state write nor a degraded target.
    @Test func everyWatchConditionReadsAsItsOwnCase() throws {
        #expect(
            try decode(WatchError.self, "watch_error") == [
                .wgReadFailed, .nftFailed, .statsQueryFailed, .targetDegraded,
                .targetReadFailed(errno: 13), .exitFlowCapHit(count: 14), .stateWrite(errno: 28),
                .macSilent(since: UnixTime(seconds: 1_791_416_400)), .diskLow(free: 950_000_000),
                .clockUnsynced, .rebootPending(since: UnixTime(seconds: 1_791_331_200)),
                .accountingCanaryMissing(inbounds: [.reality, .hy2]),
            ])
        let undecodable = try JSONDecoder().decode(
            WatchError.self, from: Data(#"{"TargetReadFailed":{"errno":null}}"#.utf8))
        #expect(undecodable == .targetReadFailed(errno: nil))
    }

    /// The fixture lists every group the mirror reads, and no other.
    @Test func everyGroupOfTheFixtureIsRead() throws {
        #expect(try Self.document().count == 63)
    }

    /// The fixture's reported node is one the operator halted after every
    /// hold had closed its gate, so each hold, the halt marker and the
    /// applied generation are read with the values the Rust builder gave
    /// them, beside the engines the halt stopped.
    @Test func theHaltedNodeIsReadWithItsHoldsHaltAndGeneration() throws {
        let reports = try decode(NodeAgentState.self, "node_agent_state").compactMap { state -> NodeReport? in
            if case .reported(let report) = state { report } else { nil }
        }
        try #require(reports.count == 1, "\(reports)")
        let report = reports[0]
        #expect(report.gate == .closed)
        #expect(report.holds.macDrain?.handshakeAtDrain == UnixTime(seconds: 1_791_453_000))
        #expect(report.handshakeAgeSecs == 600)
        #expect(report.holds.egressViolation?.at == UnixTime(seconds: 1_791_453_300))
        #expect(report.holds.egressViolation?.generation == 3)
        #expect(report.applied?.generation == 3)
        #expect(report.applied?.digest == String(repeating: "5c", count: 32))
        #expect(report.holds.operator?.at == UnixTime(seconds: 1_791_453_480))
        #expect(report.halted?.at == UnixTime(seconds: 1_791_453_540))
        #expect(report.halted?.reason == .operator)
        #expect(report.accountingAt == UnixTime(seconds: 1_791_453_510))
        #expect(report.engines.xray.run == .inactive)
        #expect(report.engines.hy2.run == .inactive)
    }

    /// A plan's line of each kind, with its bytes.
    @Test func everyPlanLineIsReadWithItsKindAndBytes() throws {
        let lines = try decode(PlanLine.self, "plan_line")
        #expect(lines.map(\.kind) == PlanLineKind.allCases)
        #expect(lines.map(\.bytes) == [500_000_000_000, 30_000_000_000])
    }

    /// The M7's own spellings, which the CLI's summary prints too.
    @Test func serviceTypesKeepTheM7sSpelling() {
        #expect(NetworkService.allCases.map(\.wire) == ["Nr5gService", "LteService"])
        #expect(DataService.allCases.map(\.wire) == ["5GSUB6", "4G", "4GPLUS"])
        #expect(ThermalState.allCases.map(\.wire) == ["Normal"])
        #expect(PowerState.allCases.map(\.wire) == ["Online", "Standby"])
        #expect(BatteryState.allCases.map(\.wire) == ["Normal"])
        #expect(ChargeSource.allCases.map(\.wire) == ["QuickCharge", "None"])
        #expect(WifiApStatus.allCases.map(\.wire) == ["Off"])
    }

    /// A band is `B` or `n` and 1 to 999 without a leading zero.
    @Test func bandsParseAsTheRustTypeDoes() {
        #expect(Band(parsing: "B3") == .lte(3))
        #expect(Band(parsing: "n78") == .nr(78))
        #expect(Band(parsing: "B999") == .lte(999))
        for refused in ["", "B", "B0", "B03", "B1000", "b3", "N78", "LTE B3", "B3a", "B-3", "B３"] {
            #expect(Band(parsing: refused) == nil, "\(refused)")
        }
    }
}
