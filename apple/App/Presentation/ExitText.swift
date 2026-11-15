// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension ExitState {
    var headline: String {
        switch self {
        case .disabled: String(localized: "Exit disabled")
        case .preflight: String(localized: "Preflight")
        case .starting: String(localized: "Starting the engine")
        case .verifying: String(localized: "Verifying the egress")
        case .serving: String(localized: "Serving")
        case .degraded: String(localized: "Serving, degraded")
        case .down: String(localized: "Down")
        case .paused: String(localized: "Paused while the Mac sleeps")
        }
    }

    var symbol: String {
        switch self {
        case .serving: "checkmark.circle.fill"
        case .degraded: "exclamationmark.circle.fill"
        case .down: "xmark.octagon.fill"
        case .disabled: "pause.circle"
        case .preflight, .starting, .verifying: "hourglass.circle"
        case .paused: "moon.circle"
        }
    }

    var tint: Color {
        switch self {
        case .serving: .green
        case .degraded: .orange
        case .down: .red
        case .disabled, .paused: .secondary
        case .preflight, .starting, .verifying: .blue
        }
    }

    /// What the state says beyond its headline: the verified address, the
    /// reasons, or why the exit is down.
    var details: [String] {
        switch self {
        case .serving(let ip, let verifiedAt):
            [String(localized: "Egress \(ip), verified \(verifiedAt.text).")]
        case .degraded(let reasons): reasons.map(\.text)
        case .down(let reason): [reason.text]
        case .disabled:
            [String(localized: "Enable it with `mooringctl exit enable`.")]
        case .preflight, .starting, .verifying, .paused: []
        }
    }
}

extension ExitState {
    /// What to do about the violation the exit is down for; `nil` for
    /// every other state.
    var remedy: String? {
        if case .down(.violation(let violation)) = self {
            violation.remedy
        } else {
            nil
        }
    }
}

extension ProbeStage {
    var text: String {
        switch self {
        case .connect: String(localized: "connect")
        case .read: String(localized: "read")
        case .parse: String(localized: "parse")
        case .proberUnavailable: String(localized: "mooring-probe not running")
        case .carrierAddressUnstable: String(localized: "carrier address unstable")
        }
    }
}

extension ProbeProtocol {
    var text: String {
        switch self {
        case .reality: "REALITY"
        case .hy2: "Hysteria2"
        }
    }
}

extension DegradedReason {
    var text: String {
        switch self {
        case .nodeProbeFailed(let node, let proto, let stage):
            String(localized: "The \(proto.text) probe through \(node.text) failed (\(stage.text)).")
        case .reachabilitySuspect(let node):
            String(localized: "\(node.text) may be blocked in China.")
        case .watchStale(let node):
            String(localized: "\(node.text)'s watch status is older than 30 s.")
        case .onBattery:
            String(localized: "The Mac runs on battery and may sleep.")
        case .powerHelperExited:
            String(localized: "The power helper exited.")
        case .ownNetworksUnreadable(let input):
            input.text
        }
    }
}

extension OwnNetworkInput {
    var text: String {
        switch self {
        case .declarations:
            String(localized: "The own-network declarations cannot be read; no declared network matches.")
        case .routerIdentities:
            String(localized: "configd's network services cannot be read; no declared network matches.")
        }
    }
}

extension DownReason {
    var text: String {
        switch self {
        case .egressInterfaceAbsent:
            String(localized: "No interface matches the egress: the M7's Ethernet adapter is not attached.")
        case .egressAmbiguous(let matches):
            String(localized: "Interfaces matching the egress: \(matches); exactly one must.")
        case .egressNoIpv4(let interface):
            String(localized: "The egress \(interface) has no IPv4 address.")
        case .egressSubnetMismatch:
            String(localized: "The egress's IPv4 address is outside the M7's subnet.")
        case .uplinkAbsent:
            String(localized: "The separate uplink is absent.")
        case .uplinkEqualsEgress:
            String(localized: "The separate uplink is the egress.")
        case .noAppliedNode:
            String(localized: "No node has confirmed a configuration yet (`mooringctl node apply`).")
        case .directProbeFailed(let node, let stage):
            String(localized: "No direct probe succeeded; the last, to \(node.text), failed (\(stage.text)).")
        case .carrierCheckUnrecorded:
            String(localized: "The line's carrier check is not recorded (`mooringctl exit record-carrier`).")
        case .simPlanUnrecorded:
            String(localized: "The SIM plan is not recorded (`mooringctl sim set-plan`).")
        case .secretsUnavailable:
            String(localized: "The keychain could not be read.")
        case .agentNotEnabled(let node):
            String(localized: "The agent on \(node.text) is not enabled.")
        case .engineSpawnFailed(let engine):
            String(localized: "\(engine.program) could not be started.")
        case .engineConfigRejected(let engine):
            String(localized: "\(engine.program) rejected its configuration.")
        case .engineStartFailed(let engine):
            String(localized: "\(engine.program) exited within 10 s of starting.")
        case .engineCrashLoop(let engine):
            String(localized: "\(engine.program) crashed five times within 10 minutes.")
        case .violation(let violation):
            String(localized: "An egress check failed, so the exit stopped itself: \(violation.text)")
        case .simCapReached(let cycleStart):
            String(
                localized:
                    "The SIM's hard stop was reached in the cycle from \(cycleStart.display); the exit stays down until the next cycle."
            )
        case .foreignNetworkAttached(let findings):
            String(
                localized:
                    "The Mac is attached to another network: \(ListFormatter.localizedString(byJoining: findings.map(\.text)))."
            )
        }
    }
}

extension Violation {
    var text: String {
        switch self {
        case .egressIsNodeAddress(let node, let ip):
            String(localized: "the egress address \(ip) is \(node.text)'s own.")
        case .outsideCarrierPrefixes(let ip):
            String(localized: "the egress address \(ip) is outside the carrier prefixes recorded for this line.")
        case .egressEqualsUplink(let ip):
            String(localized: "the egress address \(ip) is the separate uplink's.")
        case .egressMismatch(let d1, let d2, let observed):
            String(
                localized:
                    "the in-chain probe observed \(observed) between direct probes that saw \(d1) and \(d2).")
        }
    }
}

extension Violation {
    /// What to do about the latch, by what the check found (design §10.2;
    /// the runbook `swap-day.md`, section 3). `exit retry` ends each: the
    /// daemon clears the latch, probes afresh, and latches again if the
    /// cause is still there. Recording the carrier check again is a
    /// configuration change, which clears the latch by itself.
    var remedy: String {
        switch self {
        case .egressIsNodeAddress(let node, _):
            String(
                localized:
                    "Traffic left by \(node.text)'s own address, not by this line. \(node.text) was told to halt and stays halted after the latch is cleared: find the cause before `mooringctl exit retry`."
            )
        case .outsideCarrierPrefixes:
            String(
                localized:
                    "If the SIM or the carrier's address pool changed, record the new prefixes (`mooringctl exit record-carrier --replace`, then `mooringctl node apply` for each node). If the M7 left the mobile line for its Wi-Fi or Ethernet offload, turn the offload off. Then run `mooringctl exit retry`: the exit probes afresh and starts if the address passes."
            )
        case .egressEqualsUplink:
            String(
                localized:
                    "The exit's traffic left by the separate uplink, not by the M7: check the routes on both interfaces, then clear the latch with `mooringctl exit retry`."
            )
        case .egressMismatch:
            String(
                localized:
                    "With paired probes, users' traffic must leave by the address the direct probes around it see. If the carrier hands this line changing addresses, record the check again with `--pairing unpaired` (`mooringctl exit record-carrier --replace`, then `mooringctl node apply` for each node). Then run `mooringctl exit retry`: the exit probes afresh and starts if the address passes."
            )
        }
    }
}

extension Latch {
    /// A latch the state does not show, as the overview says it under the
    /// reason that stands in front of it.
    var behindLine: String {
        String(
            localized:
                "A violation found \(at.text) is latched as well: \(violation.text) It will keep the exit down once the reason above is gone; the Exit screen says what to do about it."
        )
    }
}

extension ExitSection {
    /// The time under the state's summary: when a latched violation was
    /// found, which the state's `since` is not after a daemon restart or
    /// another reason in front of the latch; otherwise since when the
    /// state holds.
    var sinceLine: String {
        if let found = violationLatchedAt {
            String(localized: "Found \(found.text). The exit stays down until the latch is cleared.")
        } else {
            String(localized: "Since \(since.text).")
        }
    }
}

extension ViolationKind {
    var text: String {
        switch self {
        case .egressIsNodeAddress: String(localized: "egress is a node's address")
        case .outsideCarrierPrefixes: String(localized: "outside the recorded carrier prefixes")
        case .egressEqualsUplink: String(localized: "egress is the uplink")
        case .egressMismatch: String(localized: "egress mismatch")
        }
    }
}

extension ForeignNetworkFinding {
    var text: String {
        switch self {
        case .routableIpv4(let interface):
            String(localized: "\(interface) has a routable IPv4 address")
        case .globalIpv6(let interface):
            String(localized: "\(interface) has a global IPv6 address")
        case .defaultRoute(let interface, .v4):
            String(localized: "\(interface) carries an IPv4 default route")
        case .defaultRoute(let interface, .v6):
            String(localized: "\(interface) carries an IPv6 default route")
        }
    }
}

extension AllowedNetwork {
    var text: String {
        switch self {
        case .own(let interface, .personalHotspot):
            String(localized: "\(interface) is your own Personal Hotspot")
        case .own(let interface, .broadband):
            String(localized: "\(interface) is your own broadband")
        case .benchmarkingTun(let interface):
            String(localized: "\(interface) is a tunnel in the benchmarking range (CFM's TUN)")
        }
    }
}

extension ProcessEnd {
    var text: String {
        switch self {
        case .exited(let code): String(localized: "exited with code \(code)")
        case .signalled(let signal): String(localized: "ended by signal \(signal)")
        }
    }
}

extension PowerSource {
    var text: String {
        switch self {
        case .ac: String(localized: "AC power")
        case .battery: String(localized: "Battery")
        }
    }
}

extension DrainOutcome {
    var text: String {
        switch self {
        case .completed: String(localized: "completed")
        case .timedOut: String(localized: "timed out")
        case .failed: String(localized: "failed")
        }
    }
}
