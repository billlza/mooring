// SPDX-License-Identifier: GPL-3.0-or-later

// The values the console shows that the mirror derives rather than reads:
// each engine's program name (the exit screen's rows and the "could not be
// started" lines), as `daemon-core`'s `Display` for `MacEngine` and
// `NodeEngine` spells it; each LTE bandwidth in megahertz (the router
// screen's carriers); and an instant as a date (every "last read" and
// event time).

import Foundation
import Testing

@testable import MooringKit

@Suite struct ConsoleMappingTests {
    @Test func everyEngineIsNamedAsItsProgram() {
        #expect(MacEngine.allCases.map(\.program) == ["mooring-exit", "mooring-probe"])
        #expect(NodeEngine.allCases.map(\.program) == ["mooring-xray", "mooring-hy2"])
    }

    @Test func everyBandwidthIsGivenInMegahertz() {
        #expect(LteBandwidth.allCases.map(\.megahertz) == [3, 5, 10, 15, 20])
    }

    @Test func anInstantIsTheDateOfItsSeconds() {
        #expect(UnixTime(seconds: 0).date == Date(timeIntervalSince1970: 0))
        #expect(UnixTime(seconds: 1_792_639_800).date == Date(timeIntervalSince1970: 1_792_639_800))
    }
}
