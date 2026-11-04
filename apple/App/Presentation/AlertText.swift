// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension Severity {
    var text: String {
        switch self {
        case .critical: String(localized: "Critical")
        case .warning: String(localized: "Warning")
        }
    }

    var tint: Color {
        switch self {
        case .critical: .red
        case .warning: .orange
        }
    }
}

extension CriticalThermalLevel {
    var text: String {
        switch self {
        case .level2: String(localized: "level 2")
        case .level3: String(localized: "level 3")
        }
    }
}

extension DegradedReasonKind {
    var text: String {
        switch self {
        case .nodeProbeFailed: String(localized: "a node's probe failed")
        case .reachabilitySuspect: String(localized: "a node may be blocked in China")
        case .watchStale: String(localized: "a node's watch is stale")
        case .onBattery: String(localized: "on battery")
        case .powerHelperExited: String(localized: "the power helper exited")
        case .ownNetworksUnreadable: String(localized: "the own-network inputs cannot be read")
        }
    }
}

extension EngineHost {
    var text: String {
        switch self {
        case .mac(let engine): String(localized: "\(engine.program) on this Mac")
        case .node(let node, let engine): String(localized: "\(engine.program) on \(node.text)")
        }
    }
}

extension AlertCondition {
    var text: String {
        switch self {
        case .exitViolation(let violations):
            String(
                localized:
                    "An egress violation is latched: \(ListFormatter.localizedString(byJoining: violations.map(\.text)))"
            )
        case .simCapReached(let cycleStart):
            String(localized: "The SIM's hard stop was reached in the cycle from \(cycleStart.display)")
        case .routerOffloadActive: String(localized: "The M7's Wi-Fi or Ethernet offload is on")
        case .routerWifiRadioOn: String(localized: "The M7's Wi-Fi radio is on")
        case .routerOverheating(let level): String(localized: "The M7 is overheating (\(level.text))")
        case .routerRestarted: String(localized: "The M7 restarted")
        case .nodeHalted(let node): String(localized: "\(node.text) halted")
        case .rollbackFailed(let node): String(localized: "A rollback failed on \(node.text)")
        case .gateCloseFailed(let node): String(localized: "Closing \(node.text)'s gate failed")
        case .engineCrashLoop(let host): String(localized: "\(host.text) is crash-looping")
        case .hostKeyMismatch(let node): String(localized: "\(node.text)'s host key does not match its pin")
        case .macSilent(let node): String(localized: "\(node.text) has no handshake from the Mac")
        case .nodeUnreachable(let node, let since):
            String(localized: "\(node.text) has been unreachable since \(since.text)")
        case .nodeDiskLow(let node, let free):
            String(localized: "\(node.text) is low on disk: \(bytes(free)) free")
        case .simWarn(let cycleStart):
            String(localized: "The SIM passed its warning in the cycle from \(cycleStart.display)")
        case .simForecastCrossing(_, let threshold, let on):
            String(localized: "The SIM is forecast to reach its \(threshold.text.lowercased()) on \(on.display)")
        case .exitDegraded(let reasons):
            String(
                localized:
                    "The exit is degraded: \(ListFormatter.localizedString(byJoining: reasons.map(\.text)))")
        case .foreignNetworkAttached(let findings):
            String(localized: "The Mac is attached to another network (findings: \(findings))")
        case .reachabilitySuspect(let node): String(localized: "\(node.text) may be blocked in China")
        case .targetDegraded(let node): String(localized: "\(node.text)'s REALITY target is degraded")
        case .targetReadFailed(let node):
            String(localized: "\(node.text) cannot read its hourly target check's result")
        case .routerNoService: String(localized: "The M7 has no service")
        case .routerOnLte: String(localized: "The M7 is on LTE, not 5G")
        case .routerThermalStepDown: String(localized: "The M7 stepped its radio down for heat")
        case .routerWeakSignal(let rsrp):
            String(localized: "The M7's signal is weak (RSRP \(Readings.tenths(rsrp)) dBm)")
        case .routerFirmwareChanged: String(localized: "The M7's firmware changed")
        case .routerUnreadSms(let count): String(localized: "Unread SMS on the M7: \(count)")
        case .routerCounterMismatch(let permille):
            String(localized: "The SIM meter and the M7's counter differ by \(permille) ‰")
        case .usersNearQuota(let count): String(localized: "Users near their quota: \(count)")
        case .usersOverQuota(let count): String(localized: "Users over their quota: \(count)")
        case .usersSuspended(let count): String(localized: "Users suspended: \(count)")
        case .usersExpiringSoon(let count): String(localized: "Users expiring soon: \(count)")
        case .usersExpired(let count): String(localized: "Users expired: \(count)")
        case .capacitySaturated: String(localized: "The uplink is saturated")
        case .exitFlowCapHit(let node, let count):
            String(localized: "Flows \(node.text)'s exit flow cap rejected: \(count)")
        case .nodeClockUnsynced(let node): String(localized: "\(node.text)'s clock is not synchronised")
        case .nodeRebootPending(let node, let since):
            String(localized: "\(node.text) has needed a reboot since \(since.text)")
        case .pendingApply(let node, let since):
            String(localized: "\(node.text) has had an apply pending since \(since.text)")
        case .operatorHoldLong(let node, let since):
            String(localized: "\(node.text)'s operator hold has lasted since \(since.text)")
        case .accountingCanaryMissing(let node, let inbounds):
            String(localized: "\(node.text) is not counting the probe's traffic on \(inbounds.text)")
        }
    }
}
