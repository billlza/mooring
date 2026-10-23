// SPDX-License-Identifier: GPL-3.0-or-later

// The router screen (design §15.6): everything the allowlist keeps of the
// M7's status, as the M7 reported it, with the time it was polled. The
// settings the exit needs off that are on are flagged as the daemon lists
// them; the console never changes them (rule 8: advisory only).

import MooringKit
import SwiftUI

struct RouterView: View {
    let model: ConsoleModel

    var body: some View {
        switch model.status?.router {
        case nil:
            ContentUnavailableView(
                "No router status yet",
                systemImage: "antenna.radiowaves.left.and.right",
                description: Text("The daemon has not reported a poll of the M7 yet.")
            )
        case .unavailable(let reason, let lastPolledAt)?:
            RouterUnavailableView(reason: reason, lastPolledAt: lastPolledAt)
        case .available(let polledAt, let status)?:
            RouterStatusForm(
                polledAt: polledAt, status: status, advisories: model.status?.advisories ?? [])
        }
    }
}

struct RouterUnavailableView: View {
    let reason: RouterUnavailableReason
    let lastPolledAt: UnixTime?

    var body: some View {
        ContentUnavailableView {
            Label(reason.title, systemImage: "antenna.radiowaves.left.and.right.slash")
        } description: {
            VStack(spacing: 8) {
                Text(reason.advice)
                if let lastPolledAt {
                    Text("Last read \(lastPolledAt.date.formatted(date: .abbreviated, time: .standard)).")
                        .foregroundStyle(.secondary)
                } else {
                    Text("Never read since the daemon started.")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct RouterStatusForm: View {
    let polledAt: UnixTime
    let status: RouterStatus
    /// The settings the exit needs off that are on, as the daemon says.
    let advisories: [RouterAdvisory]

    var body: some View {
        Form {
            if !advisories.isEmpty {
                Section {
                    Label(
                        "On: \(advisories.names). The exit needs these off; turn them off in the M7's web interface.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.orange)
                }
            }
            switch status.radio {
            case .noService:
                Section("Connection") {
                    LabeledContent("Radio", value: String(localized: "No service"))
                    LabeledContent("SIM", value: status.simSpn ?? String(localized: "name not reported"))
                }
            case .attached(let radio):
                connection(radio)
                signal(radio)
            }
            Section("Device") {
                LabeledContent("Model", value: "NETGEAR MR7450")
                LabeledContent("Firmware", value: status.firmware)
                LabeledContent("Web app", value: status.webApp ?? String(localized: "not reported"))
                LabeledContent("Up") { spanText(status.uptimeSecs) }
                LabeledContent("Temperature", value: "\(status.temperatureC) °C")
                LabeledContent("Thermal state", value: status.thermal.wire)
            }
            Section("Power") {
                LabeledContent("State", value: status.power.state.wire)
                LabeledContent(
                    "Battery",
                    value: "\(status.power.battery.charge) %, \(status.power.battery.state.wire)"
                )
                LabeledContent(
                    "Charging",
                    value: status.power.battery.charging ? String(localized: "yes") : String(localized: "no")
                )
                LabeledContent("Charge source", value: status.power.battery.source.wire)
                LabeledContent("Battery temperature", value: "\(status.power.battery.temperatureC) °C")
            }
            Section {
                LabeledContent("Received", value: Readings.bytes(status.counters.rxBytes))
                LabeledContent("Sent", value: Readings.bytes(status.counters.txBytes))
            } header: {
                Text("Traffic")
            } footer: {
                Text("The M7's own counters (wwan.dataTransferredRx/Tx).")
            }
            Section("Wi-Fi and settings") {
                flag("Wi-Fi radio", on: status.wifi.enabled)
                LabeledContent("Access points") {
                    Text(
                        "main \(status.wifi.main.wire), guest \(status.wifi.guest.wire), aux \(status.wifi.aux.wire)"
                    )
                }
                LabeledContent("Wi-Fi clients", value: "\(status.wifi.clients)")
                flag("Wi-Fi offload", on: status.settings.wifiOffload)
                flag("Ethernet offload", on: status.settings.ethernetOffload)
                flag("UPnP", on: status.settings.upnp)
                flag("Analytics", on: status.settings.analytics)
                flag("NETGEAR Insight", on: status.settings.insightActive)
            }
            Section {
                LabeledContent("Unread SMS", value: "\(status.unreadSms)")
            } footer: {
                Text("Only the count is read; read messages in the M7's web interface.")
            }
            Section {
                LabeledContent(
                    "Polled",
                    value: polledAt.date.formatted(date: .abbreviated, time: .standard)
                )
            }
        }
        .formStyle(.grouped)
    }

    private func connection(_ radio: Radio) -> some View {
        Section("Connection") {
            LabeledContent("Network", value: "\(radio.network) (\(radio.plmn.mcc)-\(radio.plmn.mnc))")
            LabeledContent("SIM", value: status.simSpn ?? String(localized: "name not reported"))
            LabeledContent("Service", value: "\(radio.networkService.wire) · \(radio.dataService.wire)")
            LabeledContent("Band", value: radio.band.text)
            LabeledContent("LTE carriers", value: carriers(radio.lteCarriers))
            LabeledContent("Secondary carriers counted", value: "\(radio.caSecondaryCount)")
            LabeledContent("Session") { spanText(radio.sessionSecs) }
        }
    }

    private func signal(_ radio: Radio) -> some View {
        Section {
            ReadingRow(label: "LTE RSRP", tenths: radio.lte.rsrp, unit: "dBm", quality: SignalQuality.rsrp)
            ReadingRow(label: "LTE RSRQ", tenths: radio.lte.rsrq, unit: "dB", quality: nil)
            ReadingRow(label: "LTE SINR", tenths: radio.lte.sinr, unit: "dB", quality: SignalQuality.sinr)
            ReadingRow(label: "LTE RSSI", tenths: radio.lte.rssi, unit: "dBm", quality: nil)
            ReadingRow(label: "NR RSRP", tenths: radio.nr.rsrp, unit: "dBm", quality: SignalQuality.rsrp)
            ReadingRow(label: "NR RSRQ", tenths: radio.nr.rsrq, unit: "dB", quality: nil)
            ReadingRow(label: "NR SINR", tenths: radio.nr.sinr, unit: "dB", quality: SignalQuality.sinr)
        } header: {
            Text("Signal")
        } footer: {
            Text(
                "Colours follow common LTE rules of thumb (RSRP −80/−90/−100 dBm, SINR 20/13/0 dB); they only help with placing the antenna."
            )
        }
    }

    private func carriers(_ carriers: LteCarriers?) -> String {
        guard let carriers else {
            return String(localized: "none listed")
        }
        let carrier = { (carrier: LteCarrier) in "B\(carrier.band) \(carrier.dlBandwidth.megahertz) MHz" }
        var parts = [String(localized: "\(carrier(carriers.primary)) (primary)")]
        parts += carriers.secondary.map(carrier)
        switch carriers.unassignedSlots {
        case 0: break
        case 1: parts.append(String(localized: "1 unassigned slot"))
        case let slots: parts.append(String(localized: "\(slots) unassigned slots"))
        }
        return parts.joined(separator: ", ")
    }

    private func flag(_ label: LocalizedStringKey, on: Bool) -> some View {
        LabeledContent(label) {
            if on {
                Label("on", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else {
                Text("off")
            }
        }
    }
}

/// One reading, with a quality colour when there is a rule for it.
struct ReadingRow: View {
    let label: LocalizedStringKey
    let tenths: Int16?
    let unit: String
    let quality: ((Int16) -> SignalQuality)?

    var body: some View {
        LabeledContent(label) {
            HStack(spacing: 6) {
                if let tenths {
                    if let quality {
                        Circle()
                            .fill(quality(tenths).color)
                            .frame(width: 8, height: 8)
                    }
                    Text(verbatim: Readings.reading(tenths, unit: unit))
                        .monospacedDigit()
                } else {
                    Text("not reported")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

extension SignalQuality {
    var color: Color {
        switch self {
        case .excellent: .green
        case .good: .mint
        case .fair: .yellow
        case .poor: .red
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .excellent: "excellent"
        case .good: "good"
        case .fair: "fair"
        case .poor: "poor"
        }
    }
}

extension RouterUnavailableReason {
    var title: LocalizedStringKey {
        switch self {
        case .notConfigured: "The router adapter is not set up"
        case .unreachable: "The M7 is unreachable"
        case .authFailed: "The M7 refused the login"
        case .identityMismatch: "The gateway is not the pinned M7"
        case .unsupported: "Not a supported M7"
        case .malformed: "The M7's answer could not be read"
        case .localFailure: "The Mac could not poll the M7"
        }
    }

    var advice: LocalizedStringKey {
        switch self {
        case .notConfigured:
            "Pin the M7 on the Mac's interface to it (`mooringctl router pin --interface en9`, which records the interface the daemon polls on) and store its admin password (`mooringctl router set-password`)."
        case .unreachable:
            "The M7 did not answer on its interface. Check that it is on and that the USB Ethernet adapter is connected."
        case .authFailed:
            "The M7 did not grant an administrator's session. If its admin password changed, store it again with `mooringctl router set-password`."
        case .identityMismatch:
            "The device answering at the gateway is not the M7 that was pinned, so no password was sent."
        case .unsupported:
            "The device answering is not an MR7450 speaking the API this build reads."
        case .malformed:
            "The M7's answer did not match what this build reads; the daemon's log names the field."
        case .localFailure:
            "The keychain or the kernel's tables failed on this Mac; the daemon's log (~/Library/Logs/Mooring/daemon.log) names the cause."
        }
    }
}

/// A span as `mooringctl` spells it (`4d 03:46:57`), its day unit in the
/// user's language.
func spanText(_ seconds: UInt64) -> Text {
    let (days, clock) = Readings.span(seconds)
    return Text("\(days) d \(clock)")
}

extension RouterAdvisory {
    /// The setting, in the user's language.
    var name: String {
        switch self {
        case .wifiRadioOn: String(localized: "Wi-Fi radio")
        case .wifiOffloadOn: String(localized: "Wi-Fi offload")
        case .ethernetOffloadOn: String(localized: "Ethernet offload")
        case .upnpOn: String(localized: "UPnP")
        case .insightActive: String(localized: "NETGEAR Insight")
        }
    }
}

extension [RouterAdvisory] {
    /// The settings, as a list in the user's language.
    var names: String {
        ListFormatter.localizedString(byJoining: map(\.name))
    }
}
