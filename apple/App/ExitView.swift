// SPDX-License-Identifier: GPL-3.0-or-later

// The exit screen (design §15.3): the exit's state and why, the latched
// violations with their evidence, the egress and the carrier check, the
// two engines, the Mac's power and any foreign network.

import MooringKit
import SwiftUI

struct ExitView: View {
    let status: DeployedStatus

    var body: some View {
        let exit = status.exit
        Form {
            Section {
                Label(exit.state.headline, systemImage: exit.state.symbol)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(exit.state.tint)
                ForEach(exit.state.details, id: \.self) { detail in
                    Text(detail)
                }
                LabeledContent("Since", value: exit.since.text)
            } header: {
                Text("State")
            } footer: {
                Text(
                    "`mooringctl exit enable`, `disable` and `retry` change it from Terminal; the console only shows it."
                )
            }
            if !exit.latches.isEmpty {
                Section {
                    ForEach(exit.latches, id: \.self) { latch in
                        LabeledContent(latch.at.text) {
                            Text(latch.violation.text)
                                .foregroundStyle(.red)
                        }
                    }
                } header: {
                    Text("Latched violations")
                } footer: {
                    Text("A latch survives daemon restarts; the exit stays down until it is cleared.")
                }
            }
            Section("Egress") {
                if let egress = exit.egress {
                    LabeledContent("Interface", value: egress.interface)
                    LabeledContent("Link-layer address", value: egress.lladdr)
                    LabeledContent("IPv4 on the M7's network", value: egress.ipv4)
                    LabeledContent("Link") {
                        Text(linkText(egress.link))
                            .foregroundStyle(egress.link.up ? Color.primary : Color.red)
                    }
                } else {
                    Text("The egress does not resolve to an interface.")
                        .foregroundStyle(.orange)
                }
            }
            Section("Carrier check") {
                if let check = exit.carrierCheck {
                    LabeledContent("Carrier address", value: check.egressIp)
                    LabeledContent("In the carrier's prefixes") {
                        Text(check.inCarrierPrefixes ? String(localized: "yes") : String(localized: "no"))
                            .foregroundStyle(check.inCarrierPrefixes ? Color.primary : Color.red)
                    }
                    LabeledContent("Pairing", value: check.pairing.text)
                    LabeledContent("Checked", value: check.checkedAt.text)
                } else {
                    Text("No direct probe has run yet.")
                        .foregroundStyle(.secondary)
                }
            }
            Section("Engines") {
                engine(.exit, exit.engines.exit)
                engine(.probe, exit.engines.probe)
            }
            Section {
                LabeledContent("Source", value: exit.power.source.text)
                LabeledContent(
                    "Assertions held",
                    value: exit.power.assertionsHeld ? String(localized: "yes") : String(localized: "no"))
                LabeledContent("Last sleep", value: exit.power.lastSleep?.text ?? String(localized: "none"))
                LabeledContent("Last wake", value: exit.power.lastWake?.text ?? String(localized: "none"))
                LabeledContent("Last drain") {
                    if let drain = exit.power.lastDrain {
                        Text("\(drain.outcome.text), \(drain.at.text)")
                    } else {
                        Text("none")
                    }
                }
            } header: {
                Text("Power")
            } footer: {
                Text("On battery the exit is degraded and the Mac may sleep; it drains the nodes before it does.")
            }
            Section("Foreign networks") {
                if exit.foreignNetworks.isEmpty {
                    Text("None: the Mac is attached to the M7 only.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(exit.foreignNetworks, id: \.self) { finding in
                        Label(finding.text, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            Section {
                if exit.allowedNetworks.isEmpty {
                    Text("None: no own network or CFM tunnel is attached.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(exit.allowedNetworks, id: \.self) { allowed in
                        Label(allowed.text, systemImage: "checkmark.shield")
                    }
                }
            } header: {
                Text("Allowed networks")
            } footer: {
                Text(
                    "Your own networks, declared with `mooringctl exit allow-network`, and CFM's tunnel keep the exit serving; every exit connection stays bound to the M7."
                )
            }
        }
        .formStyle(.grouped)
    }

    private func linkText(_ link: LinkState) -> String {
        switch (link.up, link.speedMbps) {
        case (true, let speed?): String(localized: "up, \(speed) Mbit/s")
        case (true, nil): String(localized: "up, speed not reported")
        case (false, _): String(localized: "down")
        }
    }

    private func engine(_ engine: MacEngine, _ process: EngineProcess) -> some View {
        LabeledContent(engine.program) {
            VStack(alignment: .trailing, spacing: 2) {
                if let pid = process.pid {
                    Text("running, pid \(pid)")
                } else {
                    Text("not running")
                        .foregroundStyle(.secondary)
                }
                Text("restarts: \(process.restarts)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let last = process.lastExit {
                    Text("last \(last.end.text), \(last.at.text)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}
