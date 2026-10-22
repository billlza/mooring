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

    /// The M7's own spellings, which the CLI's summary prints too.
    @Test func serviceTypesKeepTheM7sSpelling() {
        #expect(NetworkService.allCases.map(\.wire) == ["Nr5gService", "LteService"])
        #expect(DataService.allCases.map(\.wire) == ["5GSUB6", "4G", "4GPLUS"])
        #expect(ThermalState.allCases.map(\.wire) == ["Normal"])
        #expect(PowerState.allCases.map(\.wire) == ["Online"])
        #expect(BatteryState.allCases.map(\.wire) == ["Normal"])
        #expect(ChargeSource.allCases.map(\.wire) == ["QuickCharge"])
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
