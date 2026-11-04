// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension NodeRole {
    var text: String {
        switch self {
        case .primary: String(localized: "Primary")
        case .standby: String(localized: "Standby")
        }
    }
}

extension LifecycleStage {
    var text: String {
        switch self {
        case .planned: String(localized: "Planned")
        case .adopted: String(localized: "Adopted")
        case .applied: String(localized: "Applied")
        case .retiring: String(localized: "Retiring")
        case .retiredPendingProviderDeletion: String(localized: "Retired, pending deletion at the provider")
        case .retired: String(localized: "Retired")
        }
    }
}

extension GateState {
    var text: String {
        switch self {
        case .open: String(localized: "Open")
        case .closed: String(localized: "Closed")
        }
    }
}

extension ShutdownReason {
    var text: String {
        switch self {
        case .egressIsNodeAddress: String(localized: "the egress was the node's own address")
        case .operator: String(localized: "by the operator")
        case .retire: String(localized: "retired")
        }
    }
}

extension AgentUnreachable {
    var text: String {
        switch self {
        case .spawn: String(localized: "ssh could not be started")
        case .hostKeyMismatch: String(localized: "the host key did not match its pin")
        case .authFailed: String(localized: "the node refused the key")
        case .transport: String(localized: "the connection failed")
        case .timeout: String(localized: "no answer in time")
        case .protocolMismatch: String(localized: "the agent speaks another protocol version")
        case .decode: String(localized: "the answer could not be decoded")
        case .responseTooLarge: String(localized: "the answer exceeded 1 MiB")
        case .forcedCommandNotActive: String(localized: "the node's forced command is not active")
        }
    }
}

extension Inbound {
    var text: String {
        switch self {
        case .reality: "REALITY"
        case .hy2: "Hysteria2"
        }
    }
}

extension [Inbound] {
    var text: String {
        ListFormatter.localizedString(byJoining: map(\.text))
    }
}

extension WatchError {
    var text: String {
        switch self {
        case .wgReadFailed: String(localized: "Reading WireGuard state failed; the gate is closed")
        case .nftFailed: String(localized: "nft failed; the watch restarts with the gate closed")
        case .statsQueryFailed: String(localized: "The Xray stats query failed")
        case .targetDegraded: String(localized: "The REALITY target is degraded")
        case .targetReadFailed(let errno?):
            String(localized: "Reading the hourly target check's result failed (errno \(errno))")
        case .targetReadFailed(nil): String(localized: "The hourly target check's result could not be decoded")
        case .exitFlowCapHit(let count): String(localized: "Flows the exit flow cap rejected: \(count)")
        case .stateWrite(let errno?): String(localized: "Writing watch state failed (errno \(errno))")
        case .stateWrite(nil): String(localized: "Writing watch state failed")
        case .macSilent(let since?): String(localized: "No handshake from the Mac since \(since.text)")
        case .macSilent(nil): String(localized: "No handshake from the Mac")
        case .diskLow(let free): String(localized: "Low disk: \(bytes(free)) free")
        case .clockUnsynced: String(localized: "The clock is not synchronised by NTP")
        case .rebootPending(let since): String(localized: "A reboot has been required since \(since.text)")
        case .accountingCanaryMissing(let inbounds):
            String(localized: "The probe's traffic is not being counted on \(inbounds.text)")
        }
    }
}

extension EngineRun {
    var text: String {
        switch self {
        case .inactive: String(localized: "inactive")
        case .active(let uptime, let heap?):
            String(localized: "active for \(span(uptime)), Go heap \(bytes(heap))")
        case .active(let uptime, nil):
            String(localized: "active for \(span(uptime))")
        }
    }
}

extension InChainOutcome {
    var text: String {
        switch self {
        case .verified: String(localized: "Verified")
        case .violation(let kind): String(localized: "Violation: \(kind.text)")
        case .failed(let stage): String(localized: "Failed (\(stage.text))")
        }
    }

    var tint: Color {
        switch self {
        case .verified: .green
        case .violation: .red
        case .failed: .orange
        }
    }
}
