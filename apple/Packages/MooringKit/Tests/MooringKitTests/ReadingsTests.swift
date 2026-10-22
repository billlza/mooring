// SPDX-License-Identifier: GPL-3.0-or-later

import Testing

@testable import MooringKit

@Suite struct ReadingsTests {
    @Test func tenthsShowADecimalOnlyWhenThereIsOne() {
        #expect(Readings.tenths(-1040) == "-104")
        #expect(Readings.tenths(-1045) == "-104.5")
        #expect(Readings.tenths(-5) == "-0.5")
        #expect(Readings.tenths(0) == "0")
        #expect(Readings.tenths(120) == "12")
        #expect(Readings.tenths(Int16.min) == "-3276.8")
        #expect(Readings.reading(-990, unit: "dBm") == "-99 dBm")
    }

    @Test func spansAreDaysAndAClock() {
        #expect(Readings.span(0) == (0, "00:00:00"))
        #expect(Readings.span(359_217) == (4, "03:46:57"))
        #expect(Readings.span(86_399) == (0, "23:59:59"))
        #expect(Readings.span(86_400) == (1, "00:00:00"))
    }

    @Test func bytesUseDecimalUnitsRoundedDown() {
        #expect(Readings.bytes(0) == "0 B")
        #expect(Readings.bytes(999) == "999 B")
        #expect(Readings.bytes(1000) == "1.0 kB")
        #expect(Readings.bytes(1500) == "1.5 kB")
        #expect(Readings.bytes(591_655_199) == "591.6 MB")
        #expect(Readings.bytes(81_000_000_000) == "81.0 GB")
        #expect(Readings.bytes(999_999_999) == "999.9 MB")
        #expect(Readings.bytes(UInt64.max) == "18.4 EB")
    }

    @Test func signalQualityFollowsItsThresholds() {
        #expect(SignalQuality.rsrp(tenths: -800) == .excellent)
        #expect(SignalQuality.rsrp(tenths: -801) == .good)
        #expect(SignalQuality.rsrp(tenths: -900) == .good)
        #expect(SignalQuality.rsrp(tenths: -901) == .fair)
        #expect(SignalQuality.rsrp(tenths: -1000) == .fair)
        #expect(SignalQuality.rsrp(tenths: -1001) == .poor)
        #expect(SignalQuality.sinr(tenths: 200) == .excellent)
        #expect(SignalQuality.sinr(tenths: 199) == .good)
        #expect(SignalQuality.sinr(tenths: 130) == .good)
        #expect(SignalQuality.sinr(tenths: 129) == .fair)
        #expect(SignalQuality.sinr(tenths: 0) == .fair)
        #expect(SignalQuality.sinr(tenths: -1) == .poor)
    }
}
