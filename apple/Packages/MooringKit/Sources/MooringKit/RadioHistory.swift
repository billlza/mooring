// SPDX-License-Identifier: GPL-3.0-or-later

// The radio history (`mooring-daemon-core`'s `radio_history`, design §15.6
// rule 11): the document `mooringctl router history --json` prints. The
// days asked for, one sample per poll of the M7 (what it read, or why the
// poll failed), the events between the samples, and the days whose file
// ended in an incomplete line. The mirror keeps the Rust types' fields,
// closed enums and required `null`s; readings stay in tenths.

import Foundation

/// The attachment as the history keeps it: without the network's display
/// name and the carrier list.
public struct SampledAttachment: Decodable, Hashable, Sendable {
    public let networkService: NetworkService
    public let dataService: DataService
    public let band: Band
    public let caSecondaryCount: UInt8
    public let lte: LteSignal
    public let nr: NrSignal
    public let plmn: Plmn
    public let sessionSecs: UInt64

    enum CodingKeys: String, CodingKey, CaseIterable {
        case networkService = "network_service"
        case dataService = "data_service"
        case band
        case caSecondaryCount = "ca_secondary_count"
        case lte, nr, plmn
        case sessionSecs = "session_secs"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        networkService = try object.decode(NetworkService.self, forKey: .networkService)
        dataService = try object.decode(DataService.self, forKey: .dataService)
        band = try object.decode(Band.self, forKey: .band)
        caSecondaryCount = try object.decode(UInt8.self, forKey: .caSecondaryCount)
        lte = try object.decode(LteSignal.self, forKey: .lte)
        nr = try object.decode(NrSignal.self, forKey: .nr)
        plmn = try object.decode(Plmn.self, forKey: .plmn)
        sessionSecs = try object.decode(UInt64.self, forKey: .sessionSecs)
    }
}

/// The M7's attachment as a sample keeps it: `"no_service"`, or
/// `{"attached": …}`.
public enum SampledRadio: Decodable, Hashable, Sendable {
    case noService
    case attached(SampledAttachment)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("no_service", nil):
            self = .noService
        case ("attached", let value?):
            self = .attached(try SampledAttachment(from: value))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// What a status contributed to a sample.
public struct RadioReading: Decodable, Hashable, Sendable {
    public let uptimeSecs: UInt64
    public let temperatureC: Int16
    public let thermal: ThermalState
    public let radio: SampledRadio

    enum CodingKeys: String, CodingKey, CaseIterable {
        case uptimeSecs = "uptime_secs"
        case temperatureC = "temperature_c"
        case thermal, radio
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        uptimeSecs = try object.decode(UInt64.self, forKey: .uptimeSecs)
        temperatureC = try object.decode(Int16.self, forKey: .temperatureC)
        thermal = try object.decode(ThermalState.self, forKey: .thermal)
        radio = try object.decode(SampledRadio.self, forKey: .radio)
    }
}

/// A poll's outcome: `{"read": …}` or `{"failed": {"reason": …}}`.
public enum RadioPoll: Decodable, Hashable, Sendable {
    case read(RadioReading)
    case failed(RouterUnavailableReason)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.onlyKey()
        switch tag {
        case "read":
            self = .read(try RadioReading(from: value))
        case "failed":
            let object = try value.fields("reason")
            self = .failed(try object.field(RouterUnavailableReason.self, "reason"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// What one poll of the M7 left: when the Mac polled, and what it got.
public struct RadioSample: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let poll: RadioPoll

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, poll
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        poll = try object.decode(RadioPoll.self, forKey: .poll)
    }

    /// The attachment read, if the poll read one.
    public var attachment: SampledAttachment? {
        if case .read(let reading) = poll, case .attached(let radio) = reading.radio {
            return radio
        }
        return nil
    }
}

/// What changed between two polls, as `daemon-core` decides it.
public enum RadioEventKind: Decodable, Hashable, Sendable {
    case pollFailed(RouterUnavailableReason)
    case pollRecovered
    case routerRebooted
    case serviceLost
    case serviceRegained
    case networkServiceChanged(from: NetworkService, to: NetworkService)
    case dataServiceChanged(from: DataService, to: DataService)
    case bandChanged(from: Band, to: Band)
    case plmnChanged(from: Plmn, to: Plmn)
    case sessionRestarted

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("poll_recovered", nil):
            self = .pollRecovered
        case ("router_rebooted", nil):
            self = .routerRebooted
        case ("service_lost", nil):
            self = .serviceLost
        case ("service_regained", nil):
            self = .serviceRegained
        case ("session_restarted", nil):
            self = .sessionRestarted
        case ("poll_failed", let value?):
            let object = try value.fields("reason")
            self = .pollFailed(try object.field(RouterUnavailableReason.self, "reason"))
        case ("network_service_changed", let value?):
            let object = try value.fields("from", "to")
            self = .networkServiceChanged(
                from: try object.field(NetworkService.self, "from"),
                to: try object.field(NetworkService.self, "to"))
        case ("data_service_changed", let value?):
            let object = try value.fields("from", "to")
            self = .dataServiceChanged(
                from: try object.field(DataService.self, "from"),
                to: try object.field(DataService.self, "to"))
        case ("band_changed", let value?):
            let object = try value.fields("from", "to")
            self = .bandChanged(from: try object.field(Band.self, "from"), to: try object.field(Band.self, "to"))
        case ("plmn_changed", let value?):
            let object = try value.fields("from", "to")
            self = .plmnChanged(from: try object.field(Plmn.self, "from"), to: try object.field(Plmn.self, "to"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// A change, at the poll that showed it.
public struct RadioEvent: Decodable, Hashable, Sendable {
    public let at: UnixTime
    public let kind: RadioEventKind

    enum CodingKeys: String, CodingKey, CaseIterable {
        case at, kind
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        at = try object.decode(UnixTime.self, forKey: .at)
        kind = try object.decode(RadioEventKind.self, forKey: .kind)
    }
}

/// The document: the UTC days asked for, their samples in poll order, the
/// events they show, and the days whose file ended in an incomplete line.
public struct RadioHistory: Decodable, Hashable, Sendable {
    /// The version this build reads.
    public static let version: UInt32 = 1

    public let since: CalendarDate
    public let until: CalendarDate
    public let samples: [RadioSample]
    public let events: [RadioEvent]
    public let incompleteDays: [CalendarDate]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, since, until, samples, events
        case incompleteDays = "incomplete_days"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        let version = try object.decode(UInt32.self, forKey: .version)
        guard version == Self.version else {
            throw ConsoleDecodingError.unsupportedVersion(version)
        }
        since = try object.decode(CalendarDate.self, forKey: .since)
        until = try object.decode(CalendarDate.self, forKey: .until)
        samples = try object.decode([RadioSample].self, forKey: .samples)
        events = try object.decode([RadioEvent].self, forKey: .events)
        incompleteDays = try object.decode([CalendarDate].self, forKey: .incompleteDays)
    }

    /// The one line `router history --json` prints, with or without its
    /// newline.
    public static func decode(line: some DataProtocol) throws -> RadioHistory {
        try JSONDecoder().decode(RadioHistory.self, from: Data(line))
    }

    /// The samples polled at `since` or later, in their order.
    public func samples(since: UnixTime) -> [RadioSample] {
        samples.filter { $0.at >= since }
    }

    /// The events at `since` or later, in their order.
    public func events(since: UnixTime) -> [RadioEvent] {
        events.filter { $0.at >= since }
    }
}
