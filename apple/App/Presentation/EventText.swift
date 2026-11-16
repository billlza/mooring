// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words the event journals (design §15.7): each event of
// the Mac's journal and each line of a node's copy, in the user's
// language, with the words the other screens use for the same states,
// conditions and holds. The words say what the journals hold; they
// decide nothing.

import MooringKit
import SwiftUI

extension MacEventKind {
    var text: String {
        switch self {
        case .daemonStarted: String(localized: "The daemon started")
        case .powerSource(let source): String(localized: "Power source: \(source.text)")
        case .slept(let drain): String(localized: "The Mac went to sleep; draining the nodes \(drain.text)")
        case .woke: String(localized: "The Mac woke")
        case .exit(let phase): String(localized: "Exit: \(phase.headline)")
        case .nodeUnreachable(let node, let cause):
            String(localized: "\(node.text)'s agent cannot be polled: \(cause.text)")
        case .nodeReachable(let node): String(localized: "\(node.text)'s agent answers again")
        }
    }

    /// What the event says beyond its line: an exit phase's reasons.
    var details: String? {
        if case .exit(let phase) = self {
            phase.details
        } else {
            nil
        }
    }
}

extension NodeEntry {
    var text: String {
        switch self {
        case .event(let event): event.kind.text
        // MooringKit reads no gap whose `to` is not above its `from`.
        case .gap(let from, let to):
            String(localized: "Events \(from) to \(to - 1) were pruned on the node before the Mac read them")
        case .reset(let end):
            String(
                localized:
                    "The node's journal was started anew (it ends before event \(end)); the Mac reads it again from its start"
            )
        }
    }
}

extension AgentEventKind {
    var text: String {
        switch self {
        case .conditionRaised(let condition): String(localized: "Condition raised: \(condition.text)")
        case .conditionCleared(let condition): condition.clearedText
        case .gateOpened: String(localized: "The gate opened")
        case .gateClosed: String(localized: "The gate closed")
        case .holdRecorded(let hold): String(localized: "Hold recorded: \(hold.text)")
        case .holdCleared(let hold): String(localized: "Hold cleared: \(hold.text)")
        case .halted(let reason): String(localized: "Halted: \(reason.text)")
        case .resumed(let generation): String(localized: "Resumed; the engines run generation \(generation)")
        case .committed(let generation): String(localized: "Generation \(generation) committed")
        case .engineRestarted(let engine): String(localized: "systemd restarted \(engine.engine.program)")
        case .hostBooted: String(localized: "The host booted")
        }
    }
}

extension WatchErrorKind {
    /// The condition, once the watch no longer reports it.
    var clearedText: String {
        switch self {
        case .wgReadFailed: String(localized: "WireGuard state is read again")
        case .nftFailed: String(localized: "nft works again")
        case .statsQueryFailed: String(localized: "The Xray stats query works again")
        case .targetDegraded: String(localized: "The REALITY target is no longer degraded")
        case .targetReadFailed: String(localized: "The hourly target check's result is read again")
        case .exitFlowCapHit: String(localized: "The exit flow cap rejects no more flows")
        case .stateWrite: String(localized: "Watch state is written again")
        case .macSilent: String(localized: "The Mac's handshakes reach the node again")
        case .diskLow: String(localized: "Disk space is no longer low")
        case .clockUnsynced: String(localized: "The clock is synchronised by NTP again")
        case .rebootPending: String(localized: "No reboot is required any more")
        case .accountingCanaryMissing: String(localized: "The probe's traffic is counted again")
        case .abuseCut: String(localized: "No user is cut off for abuse any more")
        case .abuseSuspected: String(localized: "No user has abuse findings below the cut level any more")
        case .abuseGuardUnavailable: String(localized: "The abuse guard works again")
        }
    }
}

extension GateReason {
    var text: String {
        switch self {
        case .macDrain: String(localized: "the Mac's sleep drain")
        case .egressViolation: String(localized: "an egress violation")
        case .operator: String(localized: "the operator")
        }
    }
}
