// SPDX-License-Identifier: GPL-3.0-or-later

// The router panel (design §15.6), mirroring `mooring-daemon-core`'s
// `router` module: the same fields, the same closed enums, the same
// required `null`s. Readings are kept in the tenths the Rust types carry.

import Foundation

/// Seconds since the Unix epoch, on the Mac's clock.
public struct UnixTime: Decodable, Hashable, Comparable, Sendable {
    public let seconds: UInt64

    public init(seconds: UInt64) {
        self.seconds = seconds
    }

    public init(from decoder: any Decoder) throws {
        seconds = try decoder.singleValueContainer().decode(UInt64.self)
    }

    public static func < (lhs: UnixTime, rhs: UnixTime) -> Bool {
        lhs.seconds < rhs.seconds
    }

    /// The instant as a `Date`.
    public var date: Date {
        Date(timeIntervalSince1970: TimeInterval(seconds))
    }
}

/// The network service type the M7 reports (`wwan.currentNWserviceType`).
public enum NetworkService: String, Decodable, Sendable, CaseIterable {
    case nr5g = "nr5g"
    case lte = "lte"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .nr5g: "Nr5gService"
        case .lte: "LteService"
        }
    }
}

/// The data service type the M7 reports (`wwan.currentPSserviceType`).
public enum DataService: String, Decodable, Sendable, CaseIterable {
    case nrSub6 = "nr_sub6"
    case lte = "lte"
    case ltePlus = "lte_plus"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .nrSub6: "5GSUB6"
        case .lte: "4G"
        case .ltePlus: "4GPLUS"
        }
    }
}

/// The modem's thermal state.
public enum ThermalState: String, Decodable, Sendable, CaseIterable {
    case normal = "normal"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .normal: "Normal"
        }
    }
}

/// The M7's power management state.
public enum PowerState: String, Decodable, Sendable, CaseIterable {
    case online = "online"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .online: "Online"
        }
    }
}

/// The battery's state.
public enum BatteryState: String, Decodable, Sendable, CaseIterable {
    case normal = "normal"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .normal: "Normal"
        }
    }
}

/// What charges the battery.
public enum ChargeSource: String, Decodable, Sendable, CaseIterable {
    case quickCharge = "quick_charge"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .quickCharge: "QuickCharge"
        }
    }
}

/// A Wi-Fi access point's status.
public enum WifiApStatus: String, Decodable, Sendable, CaseIterable {
    case off = "off"

    /// The M7's own spelling.
    public var wire: String {
        switch self {
        case .off: "Off"
        }
    }
}

/// An LTE carrier's downlink bandwidth.
public enum LteBandwidth: String, Decodable, Sendable, CaseIterable {
    case mhz3 = "mhz3"
    case mhz5 = "mhz5"
    case mhz10 = "mhz10"
    case mhz15 = "mhz15"
    case mhz20 = "mhz20"

    /// Megahertz.
    public var megahertz: Int {
        switch self {
        case .mhz3: 3
        case .mhz5: 5
        case .mhz10: 10
        case .mhz15: 15
        case .mhz20: 20
        }
    }
}

/// Why no router status is available.
public enum RouterUnavailableReason: String, Decodable, Sendable, CaseIterable {
    case notConfigured = "not_configured"
    case unreachable = "unreachable"
    case authFailed = "auth_failed"
    case identityMismatch = "identity_mismatch"
    case unsupported = "unsupported"
    case malformed = "malformed"
    case localFailure = "local_failure"
}

/// The radio band in use: `B<n>` (LTE) or `n<n>` (NR), `n` in 1...999
/// without a leading zero, as the Rust `Band` reads it.
public enum Band: Decodable, Hashable, Sendable {
    case lte(UInt16)
    case nr(UInt16)

    public init(from decoder: any Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let band = Band(parsing: text) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "not a band"
                )
            )
        }
        self = band
    }

    /// Parses `B<n>` or `n<n>`; `nil` for anything else.
    public init?(parsing text: String) {
        let make: (UInt16) -> Band
        if text.hasPrefix("B") {
            make = Band.lte
        } else if text.hasPrefix("n") {
            make = Band.nr
        } else {
            return nil
        }
        let digits = text.dropFirst()
        guard (1...3).contains(digits.count),
            digits.allSatisfy({ $0.isASCII && $0.isNumber }),
            !digits.hasPrefix("0"),
            let number = UInt16(digits),
            (1...999).contains(number)
        else {
            return nil
        }
        self = make(number)
    }

    /// `B3` or `n78`.
    public var text: String {
        switch self {
        case .lte(let number): "B\(number)"
        case .nr(let number): "n\(number)"
        }
    }
}

/// One LTE carrier.
public struct LteCarrier: Decodable, Hashable, Sendable {
    public let band: UInt16
    public let dlBandwidth: LteBandwidth

    enum CodingKeys: String, CodingKey, CaseIterable {
        case band
        case dlBandwidth = "dl_bandwidth"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        band = try object.decode(UInt16.self, forKey: .band)
        dlBandwidth = try object.decode(LteBandwidth.self, forKey: .dlBandwidth)
    }
}

/// The LTE carriers: the primary, the secondaries, and how many unassigned
/// secondary slots the M7 listed.
public struct LteCarriers: Decodable, Hashable, Sendable {
    public let primary: LteCarrier
    public let secondary: [LteCarrier]
    public let unassignedSlots: UInt8

    enum CodingKeys: String, CodingKey, CaseIterable {
        case primary
        case secondary
        case unassignedSlots = "unassigned_slots"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        primary = try object.decode(LteCarrier.self, forKey: .primary)
        secondary = try object.decode([LteCarrier].self, forKey: .secondary)
        unassignedSlots = try object.decode(UInt8.self, forKey: .unassignedSlots)
    }
}

/// The LTE readings, in tenths of dBm (RSRP, RSSI) or dB (RSRQ, SINR);
/// `nil` when the M7 did not report one.
public struct LteSignal: Decodable, Hashable, Sendable {
    public let rsrp: Int16?
    public let rsrq: Int16?
    public let sinr: Int16?
    public let rssi: Int16?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case rsrp, rsrq, sinr, rssi
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        rsrp = try object.decodeNullable(Int16.self, forKey: .rsrp)
        rsrq = try object.decodeNullable(Int16.self, forKey: .rsrq)
        sinr = try object.decodeNullable(Int16.self, forKey: .sinr)
        rssi = try object.decodeNullable(Int16.self, forKey: .rssi)
    }
}

/// The NR readings, in tenths; `nil` when not reported.
public struct NrSignal: Decodable, Hashable, Sendable {
    public let rsrp: Int16?
    public let rsrq: Int16?
    public let sinr: Int16?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case rsrp, rsrq, sinr
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        rsrp = try object.decodeNullable(Int16.self, forKey: .rsrp)
        rsrq = try object.decodeNullable(Int16.self, forKey: .rsrq)
        sinr = try object.decodeNullable(Int16.self, forKey: .sinr)
    }
}

/// The network's codes.
public struct Plmn: Decodable, Hashable, Sendable {
    public let mcc: String
    public let mnc: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case mcc, mnc
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        mcc = try object.decode(String.self, forKey: .mcc)
        mnc = try object.decode(String.self, forKey: .mnc)
    }
}

/// The M7's data attachment, as it reports it.
public struct Radio: Decodable, Hashable, Sendable {
    public let networkService: NetworkService
    public let dataService: DataService
    public let band: Band
    public let lteCarriers: LteCarriers?
    public let caSecondaryCount: UInt8
    public let lte: LteSignal
    public let nr: NrSignal
    public let network: String
    public let plmn: Plmn
    public let sessionSecs: UInt64

    enum CodingKeys: String, CodingKey, CaseIterable {
        case networkService = "network_service"
        case dataService = "data_service"
        case band
        case lteCarriers = "lte_carriers"
        case caSecondaryCount = "ca_secondary_count"
        case lte, nr, network, plmn
        case sessionSecs = "session_secs"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        networkService = try object.decode(NetworkService.self, forKey: .networkService)
        dataService = try object.decode(DataService.self, forKey: .dataService)
        band = try object.decode(Band.self, forKey: .band)
        lteCarriers = try object.decodeNullable(LteCarriers.self, forKey: .lteCarriers)
        caSecondaryCount = try object.decode(UInt8.self, forKey: .caSecondaryCount)
        lte = try object.decode(LteSignal.self, forKey: .lte)
        nr = try object.decode(NrSignal.self, forKey: .nr)
        network = try object.decode(String.self, forKey: .network)
        plmn = try object.decode(Plmn.self, forKey: .plmn)
        sessionSecs = try object.decode(UInt64.self, forKey: .sessionSecs)
    }
}

/// The M7's attachment to the mobile network: `"no_service"`, or
/// `{"attached": …}`.
public enum RadioState: Decodable, Hashable, Sendable {
    case noService
    case attached(Radio)

    public init(from decoder: any Decoder) throws {
        if let single = try? decoder.singleValueContainer(), let text = try? single.decode(String.self) {
            guard text == "no_service" else {
                throw decoder.unknownVariant(text)
            }
            self = .noService
            return
        }
        let (tag, value) = try decoder.onlyKey()
        guard tag == "attached" else {
            throw decoder.unknownVariant(tag)
        }
        self = .attached(try Radio(from: value))
    }
}

/// The battery.
public struct Battery: Decodable, Hashable, Sendable {
    public let charge: UInt8
    public let state: BatteryState
    public let charging: Bool
    public let source: ChargeSource
    public let temperatureC: Int16

    enum CodingKeys: String, CodingKey, CaseIterable {
        case charge, state, charging, source
        case temperatureC = "temperature_c"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        charge = try object.decode(UInt8.self, forKey: .charge)
        state = try object.decode(BatteryState.self, forKey: .state)
        charging = try object.decode(Bool.self, forKey: .charging)
        source = try object.decode(ChargeSource.self, forKey: .source)
        temperatureC = try object.decode(Int16.self, forKey: .temperatureC)
    }
}

/// How the M7 is powered.
public struct RouterPower: Decodable, Hashable, Sendable {
    public let state: PowerState
    public let battery: Battery

    enum CodingKeys: String, CodingKey, CaseIterable {
        case state, battery
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        state = try object.decode(PowerState.self, forKey: .state)
        battery = try object.decode(Battery.self, forKey: .battery)
    }
}

/// The WWAN counters, in bytes as the M7 reports them.
public struct WwanCounters: Decodable, Hashable, Sendable {
    public let rxBytes: UInt64
    public let txBytes: UInt64

    enum CodingKeys: String, CodingKey, CaseIterable {
        case rxBytes = "rx_bytes"
        case txBytes = "tx_bytes"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        rxBytes = try object.decode(UInt64.self, forKey: .rxBytes)
        txBytes = try object.decode(UInt64.self, forKey: .txBytes)
    }
}

/// The M7's Wi-Fi.
public struct RouterWifi: Decodable, Hashable, Sendable {
    public let enabled: Bool
    public let main: WifiApStatus
    public let guest: WifiApStatus
    public let aux: WifiApStatus
    public let clients: UInt16

    enum CodingKeys: String, CodingKey, CaseIterable {
        case enabled, main, guest, aux, clients
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        enabled = try object.decode(Bool.self, forKey: .enabled)
        main = try object.decode(WifiApStatus.self, forKey: .main)
        guest = try object.decode(WifiApStatus.self, forKey: .guest)
        aux = try object.decode(WifiApStatus.self, forKey: .aux)
        clients = try object.decode(UInt16.self, forKey: .clients)
    }
}

/// The M7 settings the exit depends on staying off.
public struct RouterSettings: Decodable, Hashable, Sendable {
    public let wifiOffload: Bool
    public let ethernetOffload: Bool
    public let upnp: Bool
    public let analytics: Bool
    public let insightActive: Bool

    enum CodingKeys: String, CodingKey, CaseIterable {
        case wifiOffload = "wifi_offload"
        case ethernetOffload = "ethernet_offload"
        case upnp, analytics
        case insightActive = "insight_active"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        wifiOffload = try object.decode(Bool.self, forKey: .wifiOffload)
        ethernetOffload = try object.decode(Bool.self, forKey: .ethernetOffload)
        upnp = try object.decode(Bool.self, forKey: .upnp)
        analytics = try object.decode(Bool.self, forKey: .analytics)
        insightActive = try object.decode(Bool.self, forKey: .insightActive)
    }
}

/// What the M7 reported at one poll.
public struct RouterStatus: Decodable, Hashable, Sendable {
    public let firmware: String
    public let webApp: String?
    public let uptimeSecs: UInt64
    public let temperatureC: Int16
    public let thermal: ThermalState
    public let power: RouterPower
    public let simSpn: String?
    public let radio: RadioState
    public let counters: WwanCounters
    public let wifi: RouterWifi
    public let settings: RouterSettings
    public let unreadSms: UInt32

    enum CodingKeys: String, CodingKey, CaseIterable {
        case firmware
        case webApp = "web_app"
        case uptimeSecs = "uptime_secs"
        case temperatureC = "temperature_c"
        case thermal, power
        case simSpn = "sim_spn"
        case radio, counters, wifi, settings
        case unreadSms = "unread_sms"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        firmware = try object.decode(String.self, forKey: .firmware)
        webApp = try object.decodeNullable(String.self, forKey: .webApp)
        uptimeSecs = try object.decode(UInt64.self, forKey: .uptimeSecs)
        temperatureC = try object.decode(Int16.self, forKey: .temperatureC)
        thermal = try object.decode(ThermalState.self, forKey: .thermal)
        power = try object.decode(RouterPower.self, forKey: .power)
        simSpn = try object.decodeNullable(String.self, forKey: .simSpn)
        radio = try object.decode(RadioState.self, forKey: .radio)
        counters = try object.decode(WwanCounters.self, forKey: .counters)
        wifi = try object.decode(RouterWifi.self, forKey: .wifi)
        settings = try object.decode(RouterSettings.self, forKey: .settings)
        unreadSms = try object.decode(UInt32.self, forKey: .unreadSms)
    }

    /// Settings the exit depends on that are on, by name: each is reported
    /// as a warning, never acted on (design §15.6 rule 8: advisory).
    public var settingsOn: [String] {
        var on: [String] = []
        if wifi.enabled { on.append("Wi-Fi radio") }
        if settings.wifiOffload { on.append("Wi-Fi offload") }
        if settings.ethernetOffload { on.append("Ethernet offload") }
        if settings.upnp { on.append("UPnP") }
        if settings.analytics { on.append("Analytics") }
        if settings.insightActive { on.append("NETGEAR Insight") }
        return on
    }
}

/// The router panel: a status, or why there is none.
public enum RouterReading: Decodable, Hashable, Sendable {
    case available(polledAt: UnixTime, status: RouterStatus)
    case unavailable(reason: RouterUnavailableReason, lastPolledAt: UnixTime?)

    private enum AvailableKeys: String, CodingKey, CaseIterable {
        case polledAt = "polled_at"
        case status
    }

    private enum UnavailableKeys: String, CodingKey, CaseIterable {
        case reason
        case lastPolledAt = "last_polled_at"
    }

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.onlyKey()
        switch tag {
        case "available":
            let object = try value.strictContainer(keyedBy: AvailableKeys.self)
            self = .available(
                polledAt: try object.decode(UnixTime.self, forKey: .polledAt),
                status: try object.decode(RouterStatus.self, forKey: .status)
            )
        case "unavailable":
            let object = try value.strictContainer(keyedBy: UnavailableKeys.self)
            self = .unavailable(
                reason: try object.decode(RouterUnavailableReason.self, forKey: .reason),
                lastPolledAt: try object.decodeNullable(UnixTime.self, forKey: .lastPolledAt)
            )
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}
