// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words a deployment's status (design §15.3): each state,
// reason, condition and figure in the user's language. The words say what
// the daemon reported; they decide nothing, and what to do next names the
// `mooringctl` command, which runs in Terminal.

import MooringKit
import SwiftUI

extension UsageErrorKind {
    var text: String {
        switch self {
        case .ledgerCorrupt: String(localized: "the collected usage ledger is invalid")
        case .monthlyInconsistent: String(localized: "monthly usage contradicts an earlier sample or its detailed bins")
        case .storeUnavailable: String(localized: "the collected usage store could not be read or written")
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
        case .revoked(let since): String(localized: "Revoked since \(since.text)")
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
