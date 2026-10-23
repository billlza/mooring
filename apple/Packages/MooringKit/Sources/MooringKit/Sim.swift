// SPDX-License-Identifier: GPL-3.0-or-later

// The SIM meter's section of a deployment's status (`mooring-daemon-core`'s
// `status::SimMeterStatus`, design §10.1 step 5, §15.2): the billing cycle,
// the line's bytes, whether they are exact, the thresholds with the stop
// policy and the plan's line, and the forecast.

import Foundation

/// A billing cycle: its first day and the first day of the next.
public struct BillingCycle: Decodable, Hashable, Sendable {
    public let start: CalendarDate
    public let nextStart: CalendarDate

    enum CodingKeys: String, CodingKey, CaseIterable {
        case start
        case nextStart = "next_start"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        start = try object.decode(CalendarDate.self, forKey: .start)
        nextStart = try object.decode(CalendarDate.self, forKey: .nextStart)
    }
}

/// Whether the SIM meter counts every byte.
public enum MeterAccuracy: String, Decodable, Sendable, CaseIterable {
    /// The egress counters see all of the SIM's traffic.
    case exact
    /// Some traffic may bypass them: the figures are a lower bound.
    case lowerBound = "lower_bound"
}

/// What happens at the stop.
public enum StopPolicy: Decodable, Hashable, Sendable {
    /// The exit stops at `bytes` until the cycle resets.
    case hardStop(bytes: UInt64)
    /// The operator's explicit choice to keep serving past an unlimited
    /// plan's fair-use line, accepting that the carrier may deprioritise
    /// the line.
    case acceptDeprioritisation

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("hard_stop", let value?):
            self = .hardStop(bytes: try value.fields("bytes").field(UInt64.self, "bytes"))
        case ("accept_deprioritisation", nil):
            self = .acceptDeprioritisation
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// The kind of a plan's line.
public enum PlanLineKind: String, Decodable, Sendable, CaseIterable {
    case fairUse = "fair_use"
    case allowance
}

/// A plan's line: a fair-use line or an allowance.
public struct PlanLine: Decodable, Hashable, Sendable {
    public let kind: PlanLineKind
    public let bytes: UInt64

    enum CodingKeys: String, CodingKey, CaseIterable {
        case kind, bytes
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        kind = try object.decode(PlanLineKind.self, forKey: .kind)
        bytes = try object.decode(UInt64.self, forKey: .bytes)
    }
}

/// The cycle's thresholds.
public struct SimThresholds: Decodable, Hashable, Sendable {
    public let warnBytes: UInt64
    public let stop: StopPolicy
    /// The plan's line; `nil` for a plan without one.
    public let planLine: PlanLine?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case warnBytes = "warn_bytes"
        case stop
        case planLine = "plan_line"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        warnBytes = try object.decode(UInt64.self, forKey: .warnBytes)
        stop = try object.decode(StopPolicy.self, forKey: .stop)
        planLine = try object.decodeNullable(PlanLine.self, forKey: .planLine)
    }
}

/// A threshold the forecast follows.
public enum SimThreshold: String, Decodable, Sendable, CaseIterable {
    case warn
    case hardStop = "hard_stop"
    case fairUse = "fair_use"
    case allowance
}

/// When a threshold is crossed.
public enum Crossing: Decodable, Hashable, Sendable {
    /// Reached on that day.
    case reached(on: CalendarDate)
    /// Projected for that day.
    case projected(on: CalendarDate)
    /// Not within this cycle at the current rate.
    case notThisCycle

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("reached", let value?):
            self = .reached(on: try value.fields("on").field(CalendarDate.self, "on"))
        case ("projected", let value?):
            self = .projected(on: try value.fields("on").field(CalendarDate.self, "on"))
        case ("not_this_cycle", nil):
            self = .notThisCycle
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// One threshold's crossing.
public struct ThresholdCrossing: Decodable, Hashable, Sendable {
    public let threshold: SimThreshold
    public let bytes: UInt64
    public let crossing: Crossing

    enum CodingKeys: String, CodingKey, CaseIterable {
        case threshold, bytes, crossing
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        threshold = try object.decode(SimThreshold.self, forKey: .threshold)
        bytes = try object.decode(UInt64.self, forKey: .bytes)
        crossing = try object.decode(Crossing.self, forKey: .crossing)
    }
}

/// The cycle's forecast: the daily average so far, projected linearly.
public struct SimForecast: Decodable, Hashable, Sendable {
    public let cycle: BillingCycle
    public let asOf: UnixTime
    public let usedBytes: UInt64
    public let dailyAverageBytes: UInt64
    public let projectedBytes: UInt64
    public let crossings: [ThresholdCrossing]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case cycle
        case asOf = "as_of"
        case usedBytes = "used_bytes"
        case dailyAverageBytes = "daily_average_bytes"
        case projectedBytes = "projected_bytes"
        case crossings
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        cycle = try object.decode(BillingCycle.self, forKey: .cycle)
        asOf = try object.decode(UnixTime.self, forKey: .asOf)
        usedBytes = try object.decode(UInt64.self, forKey: .usedBytes)
        dailyAverageBytes = try object.decode(UInt64.self, forKey: .dailyAverageBytes)
        projectedBytes = try object.decode(UInt64.self, forKey: .projectedBytes)
        crossings = try object.decode([ThresholdCrossing].self, forKey: .crossings)
    }
}

/// Why no forecast could be made.
public enum ForecastErrorKind: String, Decodable, Sendable, CaseIterable {
    case noBins = "NoBins"
    case nothingElapsed = "NothingElapsed"
    case binOutsideCycle = "BinOutsideCycle"
    case binsOutOfOrder = "BinsOutOfOrder"
    case missingDay = "MissingDay"
    case counterOverflow = "CounterOverflow"
    case model = "Model"
}

/// The forecast, or why there is none.
public enum ForecastView: Decodable, Hashable, Sendable {
    case projected(SimForecast)
    case unavailable(reason: ForecastErrorKind)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("projected", let value?):
            self = .projected(try SimForecast(from: value))
        case ("unavailable", let value?):
            self = .unavailable(reason: try value.fields("reason").field(ForecastErrorKind.self, "reason"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// The SIM meter.
public struct SimMeterStatus: Decodable, Hashable, Sendable {
    public let cycle: BillingCycle
    public let rxBytes: UInt64
    public let txBytes: UInt64
    public let accuracy: MeterAccuracy
    public let thresholds: SimThresholds
    public let forecast: ForecastView

    enum CodingKeys: String, CodingKey, CaseIterable {
        case cycle
        case rxBytes = "rx_bytes"
        case txBytes = "tx_bytes"
        case accuracy, thresholds, forecast
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        cycle = try object.decode(BillingCycle.self, forKey: .cycle)
        rxBytes = try object.decode(UInt64.self, forKey: .rxBytes)
        txBytes = try object.decode(UInt64.self, forKey: .txBytes)
        accuracy = try object.decode(MeterAccuracy.self, forKey: .accuracy)
        thresholds = try object.decode(SimThresholds.self, forKey: .thresholds)
        forecast = try object.decode(ForecastView.self, forKey: .forecast)
    }
}
