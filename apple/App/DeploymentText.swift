// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension UnixTime {
    /// The day and time, in the user's calendar and time zone.
    var text: String {
        date.formatted(date: .abbreviated, time: .standard)
    }
}

extension CalendarDate {
    /// The UTC day as the daemon wrote it, `YYYY-MM-DD`.
    var display: String { text }
}

/// Bytes as the console spells them.
func bytes(_ count: UInt64) -> String {
    Readings.bytes(count)
}

/// A rate in bit/s, in decimal units.
func rate(_ bitsPerSecond: UInt64) -> String {
    let megabits = Double(bitsPerSecond) / 1_000_000
    return megabits.formatted(.number.precision(.fractionLength(1))) + " Mbit/s"
}

/// A span in seconds, as `mooringctl` spells it.
func span(_ seconds: UInt64) -> String {
    let (days, clock) = Readings.span(seconds)
    return String(localized: "\(days) d \(clock)")
}

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
            String(localized: "A violation is latched: \(violation.text)")
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
            String(localized: "the egress address \(ip) is outside the carrier's prefixes.")
        case .egressEqualsUplink(let ip):
            String(localized: "the egress address \(ip) is the separate uplink's.")
        case .egressMismatch(let d1, let d2, let observed):
            String(
                localized:
                    "the in-chain probe observed \(observed) between direct probes that saw \(d1) and \(d2).")
        }
    }
}

extension ViolationKind {
    var text: String {
        switch self {
        case .egressIsNodeAddress: String(localized: "egress is a node's address")
        case .outsideCarrierPrefixes: String(localized: "outside the carrier's prefixes")
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
        case .personalHotspot(let interface):
            String(localized: "\(interface) is a Personal Hotspot")
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

extension Pairing {
    var text: String {
        switch self {
        case .paired: String(localized: "paired")
        case .unpaired: String(localized: "unpaired")
        }
    }
}

extension MeterAccuracy {
    var text: String {
        switch self {
        case .exact: String(localized: "Exact")
        case .lowerBound:
            String(localized: "Lower bound: the M7's Wi-Fi or offload is on, or a counter reset was seen")
        }
    }
}

extension StopPolicy {
    var text: String {
        switch self {
        case .hardStop(let stop): String(localized: "Hard stop at \(bytes(stop))")
        case .acceptDeprioritisation:
            String(localized: "Keep serving past the fair-use line, accepting deprioritisation")
        }
    }
}

extension PlanLineKind {
    var text: String {
        switch self {
        case .fairUse: String(localized: "Fair-use line")
        case .allowance: String(localized: "Allowance")
        }
    }
}

extension SimThreshold {
    var text: String {
        switch self {
        case .warn: String(localized: "Warning")
        case .hardStop: String(localized: "Hard stop")
        case .fairUse: String(localized: "Fair-use line")
        case .allowance: String(localized: "Allowance")
        }
    }
}

extension Crossing {
    var text: String {
        switch self {
        case .reached(let on): String(localized: "reached on \(on.display)")
        case .projected(let on): String(localized: "projected for \(on.display)")
        case .notThisCycle: String(localized: "not this cycle")
        }
    }

    var tint: Color {
        switch self {
        case .reached: .red
        case .projected: .orange
        case .notThisCycle: .secondary
        }
    }
}

extension ForecastErrorKind {
    var text: String {
        switch self {
        case .noBins: String(localized: "no metered day yet: there is nothing to project from")
        case .nothingElapsed: String(localized: "no time has passed in the billing cycle")
        case .binOutsideCycle: String(localized: "a metered day lies outside the cycle's elapsed days")
        case .binsOutOfOrder: String(localized: "a metered day repeats or precedes an earlier one")
        case .missingDay: String(localized: "a metered day is missing")
        case .counterOverflow: String(localized: "the SIM byte counts overflow a 64-bit counter")
        case .model: String(localized: "the plan's figures are inconsistent")
        }
    }
}

extension UsageErrorKind {
    var text: String {
        switch self {
        case .ledgerGap: String(localized: "a node's usage ledger has a gap or overlap")
        case .duplicateLedger: String(localized: "two usage ledgers are for one node")
        case .missingLedger: String(localized: "a node may have counted traffic, but no usage ledger is given for it")
        case .ledgerForUnknownNode: String(localized: "a usage ledger is for a node the deployment does not hold")
        case .periodBeforeLedger: String(localized: "a node's usage ledger starts after the period does")
        case .notCoveredThrough: String(localized: "a node's usage is not yet recorded to the report's end")
        case .binStraddlesThrough: String(localized: "a node's usage bin straddles the report's end")
        case .principalNotAUser: String(localized: "a node accounts traffic for a name that is no Mooring user id")
        case .unknownUser: String(localized: "a node accounts traffic for a user the deployment does not hold")
        case .counterOverflow: String(localized: "a usage total overflows a 64-bit counter")
        case .model: String(localized: "the deployment's figures are inconsistent")
        }
    }
}

extension UserStatus {
    var text: String {
        switch self {
        case .active: String(localized: "Active")
        case .suspended(let reason, let since):
            String(localized: "Suspended (\(reason.text)) since \(since.text)")
        case .revokePending: String(localized: "Revocation pending")
        case .revoked: String(localized: "Revoked")
        }
    }

    /// The state in a word, for a table's column.
    var shortText: String {
        switch self {
        case .active: String(localized: "Active")
        case .suspended: String(localized: "Suspended")
        case .revokePending: String(localized: "Revocation pending")
        case .revoked: String(localized: "Revoked")
        }
    }

    var tint: Color {
        switch self {
        case .active: .green
        case .suspended: .orange
        case .revokePending, .revoked: .secondary
        }
    }
}

extension SuspendReason {
    var text: String {
        switch self {
        case .operator: String(localized: "by the operator")
        case .quotaExceeded(let cycleStart):
            String(localized: "quota exceeded in the cycle from \(cycleStart.display)")
        case .expired: String(localized: "expired")
        case .abuseReview: String(localized: "abuse review")
        }
    }
}

extension ActiveNow {
    var text: String {
        switch self {
        case .active: String(localized: "active now")
        case .idle: String(localized: "idle")
        case .unknown: String(localized: "unknown")
        }
    }
}

extension QuotaState {
    var text: String {
        switch self {
        case .noQuota: String(localized: "No quota")
        case .within(let used, let quota):
            String(localized: "\(bytes(used)) of \(bytes(quota))")
        case .warn(let used, let quota):
            String(localized: "\(bytes(used)) of \(bytes(quota)), near the quota")
        case .over(let used, let quota):
            String(localized: "\(bytes(used)) of \(bytes(quota)), over the quota")
        case .usageUnavailable(let quota):
            String(localized: "Quota \(bytes(quota)); usage unavailable")
        }
    }
}

extension ExpiryState {
    var text: String {
        switch self {
        case .noExpiry: String(localized: "No expiry")
        case .expires(let at, let daysLeft):
            String(localized: "Expires \(at.text) (days left: \(daysLeft))")
        case .expired(let at): String(localized: "Expired \(at.text)")
        }
    }
}

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
                    "An egress violation is latched: \(ListFormatter.localizedString(byJoining: violations.map(\.text)))")
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

extension UplinkUse {
    var text: String {
        switch self {
        case .noBaseline: String(localized: "no uplink baseline recorded")
        case .measured(let permille, let baseline):
            String(
                localized:
                    "\((Double(permille) / 10).formatted(.number.precision(.fractionLength(1)))) % of the baseline's median, \(rate(baseline))"
            )
        }
    }
}

extension Saturation {
    var text: String {
        switch self {
        case .noEvidence: String(localized: "no evidence yet")
        case .clear: String(localized: "clear")
        case .building(let since): String(localized: "building since \(since.text)")
        case .saturated(let since): String(localized: "saturated since \(since.text)")
        }
    }

    var tint: Color {
        switch self {
        case .noEvidence, .clear: .secondary
        case .building: .orange
        case .saturated: .red
        }
    }
}
