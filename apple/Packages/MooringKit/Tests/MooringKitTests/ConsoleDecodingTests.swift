// SPDX-License-Identifier: GPL-3.0-or-later

// The Codable mirror against the Rust-generated fixtures (design §15.2):
// what it reads from them, and that it refuses what the Rust types refuse.

import Foundation
import Testing

@testable import MooringKit

@Suite struct ConsoleDecodingTests {
    @Test func theUndeployedDocumentReadsAsTheRustBuilderMadeIt() throws {
        let status = try ConsoleStatus.decode(line: try Fixtures.console("no-deployment"))
        guard case .noDeployment(let undeployed) = status else {
            Issue.record("not an undeployed document")
            return
        }
        #expect(undeployed.at == UnixTime(seconds: 1_792_639_800))
        #expect(undeployed.advisories == [.upnpOn])
        #expect(status.advisories == [.upnpOn])
        guard case .available(let polledAt, let router) = undeployed.router else {
            Issue.record("the router is not available")
            return
        }
        #expect(polledAt == UnixTime(seconds: 1_792_639_780))
        #expect(router.firmware == "NTGX75_10.04.43.01")
        #expect(router.webApp == nil)
        #expect(router.simSpn == nil)
        #expect(router.uptimeSecs == 523_014)
        #expect(router.temperatureC == 44)
        #expect(router.thermal == .normal)
        #expect(router.power.state == .online)
        #expect(router.power.battery.charge == 100)
        #expect(router.power.battery.source == .quickCharge)
        #expect(router.counters.rxBytes == 81_000_000_000)
        #expect(router.counters.txBytes == 16_412_311_040)
        #expect(router.wifi.enabled == false)
        #expect(router.wifi.clients == 0)
        #expect(router.settings.upnp)
        #expect(!router.settings.analytics && !router.settings.insightActive)
        #expect(router.unreadSms == 0)
        guard case .attached(let radio) = router.radio else {
            Issue.record("the radio is not attached")
            return
        }
        #expect(radio.networkService == .lte)
        #expect(radio.dataService == .ltePlus)
        #expect(radio.dataService.wire == "4GPLUS")
        #expect(radio.band == .lte(3))
        #expect(radio.band.text == "B3")
        #expect(radio.lteCarriers?.primary.band == 3)
        #expect(radio.lteCarriers?.primary.dlBandwidth == .mhz20)
        #expect(radio.lteCarriers?.secondary == [])
        #expect(radio.lteCarriers?.unassignedSlots == 1)
        #expect(radio.caSecondaryCount == 0)
        #expect(radio.lte.rsrp == -1000)
        #expect(radio.lte.rsrq == -120)
        #expect(radio.lte.sinr == 20)
        #expect(radio.lte.rssi == -690)
        #expect(radio.nr.rsrp == nil && radio.nr.rsrq == nil && radio.nr.sinr == nil)
        #expect(radio.network == "3 UK")
        #expect(radio.plmn.mcc == "234" && radio.plmn.mnc == "20")
        #expect(radio.sessionSecs == 86_400)
    }

    @Test func anUnavailableRouterKeepsItsReasonAndLastRead() throws {
        let status = try ConsoleStatus.decode(
            line: try Fixtures.console("no-deployment-router-unavailable"))
        #expect(status.at == UnixTime(seconds: 1_792_639_800))
        #expect(
            status.router
                == .unavailable(reason: .localFailure, lastPolledAt: UnixTime(seconds: 1_792_639_740)))
        #expect(status.advisories == [])
    }

    /// A deployment's document reads whole, with the router and the time
    /// where the undeployed one keeps them.
    @Test func aDeploymentReadsWhole() throws {
        let status = try ConsoleStatus.decode(line: try Fixtures.console("deployed"))
        guard case .deployed(let deployed) = status else {
            Issue.record("not a deployment's document")
            return
        }
        #expect(status.deployed == deployed)
        #expect(status.at == deployed.at)
        #expect(status.router == deployed.router)
        #expect(status.advisories == [])
        #expect(deployed.sortedNodes.map(\.id.text) == ["ams1", "lon1"])
    }

    /// Every object of both undeployed fixtures refuses an unknown key, as
    /// `deny_unknown_fields` does on the Rust side.
    @Test(arguments: ["no-deployment", "no-deployment-router-unavailable"])
    func everyObjectRefusesAnUnknownKey(_ name: String) throws {
        let json = try Fixtures.json(try Fixtures.console(name))
        _ = try ConsoleStatus.decode(line: try Fixtures.encode(json))
        let paths = JsonEdits.objectPaths(json)
        #expect(paths.count >= (name == "no-deployment" ? 15 : 3))
        for path in paths {
            let edited = JsonEdits.inserting(into: json, at: path)
            #expect(throws: (any Error).self, "accepted an unknown key at \(path)") {
                try ConsoleStatus.decode(line: try Fixtures.encode(edited))
            }
        }
    }

    /// A value a closed enum does not name, a tag no variant has, a missing
    /// `null`, and a document of another version are all refused.
    @Test func closedValuesAndRequiredNullsAreEnforced() throws {
        let line = String(decoding: try Fixtures.console("no-deployment"), as: UTF8.self)
        for (from, to) in [
            ("\"network_service\": \"lte\"", "\"network_service\": \"lte5\""),
            ("\"data_service\": \"lte_plus\"", "\"data_service\": \"4GPLUS\""),
            ("\"dl_bandwidth\": \"mhz20\"", "\"dl_bandwidth\": \"mhz25\""),
            ("\"band\": \"B3\"", "\"band\": \"B03\""),
            ("\"band\": \"B3\"", "\"band\": \"LTE B3\""),
            ("\"no_deployment\"", "\"undeployed\""),
            ("\"available\"", "\"present\""),
            ("\"sim_spn\": null,", ""),
            ("\"web_app\": null,", ""),
            ("\"unassigned_slots\": 1", "\"unassigned_slots\": 256"),
            ("\"temperature_c\": 44", "\"temperature_c\": 44.5"),
            ("\"upnp_on\"", "\"upnp_off\""),
            (",\n    \"advisories\": [\n      \"upnp_on\"\n    ]", ""),
        ] {
            #expect(line.contains(from), "\(from)")
            #expect(throws: (any Error).self, "\(to)") {
                try ConsoleStatus.decode(line: Data(line.replacingOccurrences(of: from, with: to).utf8))
            }
        }
        #expect(throws: ConsoleDecodingError.unsupportedVersion(2)) {
            try ConsoleStatus.decode(
                line: Data(line.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2").utf8))
        }
    }

    /// A radio with no service is the bare string, as Rust spells it.
    @Test func noServiceIsTheBareString() throws {
        #expect(try JSONDecoder().decode(RadioState.self, from: Data("\"no_service\"".utf8)) == .noService)
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(RadioState.self, from: Data("\"attached\"".utf8))
        }
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(RadioState.self, from: Data("{\"no_service\":null}".utf8))
        }
    }
}
