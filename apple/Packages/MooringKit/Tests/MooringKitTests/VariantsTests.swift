// SPDX-License-Identifier: GPL-3.0-or-later

// `contract/status-fixtures/variants.json` holds one value of every variant
// of every enum a status carries. The router's enums are read from it here,
// and each Swift enum has exactly as many cases as the Rust one has
// variants, so a variant added on either side fails a test.

import Foundation
import Testing

@testable import MooringKit

@Suite struct VariantsTests {
    private func list(_ key: String) throws -> [Any] {
        let document = try Fixtures.json(try Fixtures.data("contract/status-fixtures/variants.json"))
        guard let object = document as? [String: Any], let list = object[key] as? [Any] else {
            throw CocoaError(.coderValueNotFound)
        }
        return list
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
        #expect(readings.count == 2)
        guard case .available = readings[0], case .unavailable(.identityMismatch, nil) = readings[1]
        else {
            Issue.record("unexpected readings \(readings)")
            return
        }
        let radios = try decode(RadioState.self, "radio_state")
        #expect(radios.count == 2)
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
        #expect(try decode(PlanLineKind.self, "plan_line_kind") == PlanLineKind.allCases)
        #expect(try decode(GateState.self, "gate_state") == GateState.allCases)
        #expect(try decode(ShutdownReason.self, "shutdown_reason") == ShutdownReason.allCases)
        #expect(try decode(Inbound.self, "inbound") == Inbound.allCases)
    }

    /// Every enum with fields, read from the fixture's list for it: one
    /// value of each variant, each different, as many as the Swift enum has
    /// cases. A variant the Rust side adds is a value the mirror refuses.
    @Test func everyDeploymentVariantWithFieldsIsRead() throws {
        try distinct(ExitState.self, "exit_state", cases: 8)
        try distinct(DegradedReason.self, "degraded_reason", cases: 6)
        try distinct(DownReason.self, "down_reason", cases: 19)
        try distinct(ProcessEnd.self, "process_end", cases: 2)
        try distinct(ForecastView.self, "forecast_view", cases: 2)
        try distinct(UsageView.self, "usage_view", cases: 2)
        try distinct(InChainOutcome.self, "in_chain_outcome", cases: 3)
        try distinct(NodeAgentState.self, "node_agent_state", cases: 3)
        try distinct(AlertCondition.self, "alert_condition", cases: 39)
        try distinct(EngineHost.self, "engine_host", cases: 2)
        try distinct(Crossing.self, "crossing", cases: 3)
        try distinct(UplinkUse.self, "uplink_use", cases: 2)
        try distinct(Saturation.self, "saturation", cases: 4)
        try distinct(ForeignNetworkFinding.self, "foreign_network_finding", cases: 3)
        try distinct(AllowedNetwork.self, "allowed_network", cases: 2)
        try distinct(QuotaState.self, "quota_state", cases: 5)
        try distinct(ExpiryState.self, "expiry_state", cases: 3)
        try distinct(UserStatus.self, "user_status", cases: 4)
        try distinct(SuspendReason.self, "suspend_reason", cases: 4)
        try distinct(Violation.self, "violation", cases: 4)
        try distinct(StopPolicy.self, "stop_policy", cases: 2)
        try distinct(WatchError.self, "watch_error", cases: 11)
        try distinct(EngineRun.self, "engine_run", cases: 2)
    }

    /// `key`'s list decodes as `cases` different values.
    private func distinct<T: Decodable & Hashable>(_ type: T.Type, _ key: String, cases: Int) throws {
        let values = try decode(T.self, key)
        #expect(values.count == cases, "\(key)")
        #expect(Set(values).count == cases, "\(key)")
    }

    /// The fixture lists every group the mirror reads, and no other.
    @Test func everyGroupOfTheFixtureIsRead() throws {
        let document = try Fixtures.json(try Fixtures.data("contract/status-fixtures/variants.json"))
        guard let object = document as? [String: Any] else {
            throw CocoaError(.coderValueNotFound)
        }
        #expect(object.count == 62)
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
