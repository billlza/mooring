// SPDX-License-Identifier: GPL-3.0-or-later

// The users of a deployment's status (`mooring-daemon-core`'s
// `status::UserRow` and `UsageView`, design §15.2, §15.3): one row per
// opaque user id, with the alias, the lifecycle state, the nodes holding
// the user's credentials, recent activity, usage when there is a report,
// the quota and the expiry. Bytes and times only (design §15.5).

import Foundation

/// The periods every user row's usage covers.
public struct UsagePeriods: Decodable, Hashable, Sendable {
    /// The end of the period counted.
    public let through: UnixTime
    public let utcDay: CalendarDate
    public let cycle: BillingCycle
    public let utcMonthStart: CalendarDate

    enum CodingKeys: String, CodingKey, CaseIterable {
        case through
        case utcDay = "utc_day"
        case cycle
        case utcMonthStart = "utc_month_start"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        through = try object.decode(UnixTime.self, forKey: .through)
        utcDay = try object.decode(CalendarDate.self, forKey: .utcDay)
        cycle = try object.decode(BillingCycle.self, forKey: .cycle)
        utcMonthStart = try object.decode(CalendarDate.self, forKey: .utcMonthStart)
    }
}

/// Why the users' usage figures are unavailable.
public enum UsageErrorKind: String, Decodable, Sendable, CaseIterable {
    case ledgerGap = "LedgerGap"
    case duplicateLedger = "DuplicateLedger"
    case missingLedger = "MissingLedger"
    case ledgerForUnknownNode = "LedgerForUnknownNode"
    case periodBeforeLedger = "PeriodBeforeLedger"
    case notCoveredThrough = "NotCoveredThrough"
    case binStraddlesThrough = "BinStraddlesThrough"
    case principalNotAUser = "PrincipalNotAUser"
    case unknownUser = "UnknownUser"
    case counterOverflow = "CounterOverflow"
    case model = "Model"
}

/// Whether the user rows carry usage: a report over these periods, or why
/// none does. Usage is never shown as zeros.
public enum UsageView: Decodable, Hashable, Sendable {
    case report(periods: UsagePeriods)
    case unavailable(reason: UsageErrorKind)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("report", let value?):
            self = .report(periods: try value.fields("periods").field(UsagePeriods.self, "periods"))
        case ("unavailable", let value?):
            self = .unavailable(reason: try value.fields("reason").field(UsageErrorKind.self, "reason"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// Why a user is suspended.
public enum SuspendReason: Decodable, Hashable, Sendable {
    case `operator`
    case quotaExceeded(cycleStart: CalendarDate)
    case expired
    case abuseReview

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("operator", nil): self = .operator
        case ("quota_exceeded", let value?):
            self = .quotaExceeded(
                cycleStart: try value.fields("cycle_start").field(CalendarDate.self, "cycle_start"))
        case ("expired", nil): self = .expired
        case ("abuse_review", nil): self = .abuseReview
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// A user's lifecycle state.
public enum UserStatus: Decodable, Hashable, Sendable {
    case active
    case suspended(reason: SuspendReason, since: UnixTime)
    case revokePending
    case revoked

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("active", nil): self = .active
        case ("suspended", let value?):
            let object = try value.fields("reason", "since")
            self = .suspended(
                reason: try object.field(SuspendReason.self, "reason"),
                since: try object.field(UnixTime.self, "since"))
        case ("revoke_pending", nil): self = .revokePending
        case ("revoked", nil): self = .revoked
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// Whether a user is active now; never a guess.
public enum ActiveNow: String, Decodable, Sendable, CaseIterable {
    case active, idle
    /// A node serving the user has no fresh accounting poll.
    case unknown
}

/// When a user was last seen on a node, per protocol.
public struct ProtocolActivity: Decodable, Hashable, Sendable {
    public let reality: UnixTime?
    public let hy2: UnixTime?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case reality, hy2
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        reality = try object.decodeNullable(UnixTime.self, forKey: .reality)
        hy2 = try object.decodeNullable(UnixTime.self, forKey: .hy2)
    }
}

/// A user's recent activity.
public struct UserActivity: Decodable, Hashable, Sendable {
    public let activeNow: ActiveNow
    public let lastSeen: UnixTime?
    public let byNode: [NodeId: ProtocolActivity]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case activeNow = "active_now"
        case lastSeen = "last_seen"
        case byNode = "by_node"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        activeNow = try object.decode(ActiveNow.self, forKey: .activeNow)
        lastSeen = try object.decodeNullable(UnixTime.self, forKey: .lastSeen)
        byNode = try object.decode([NodeId: ProtocolActivity].self, forKey: .byNode)
    }
}

/// Proxied payload bytes: up is client to destination (Xray's uplink),
/// down destination to client.
public struct Traffic: Decodable, Hashable, Sendable {
    public let uplink: UInt64
    public let downlink: UInt64

    enum CodingKeys: String, CodingKey, CaseIterable {
        case uplink, downlink
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        uplink = try object.decode(UInt64.self, forKey: .uplink)
        downlink = try object.decode(UInt64.self, forKey: .downlink)
    }
}

/// Traffic per protocol.
public struct ProtocolTraffic: Decodable, Hashable, Sendable {
    public let reality: Traffic
    public let hy2: Traffic

    enum CodingKeys: String, CodingKey, CaseIterable {
        case reality, hy2
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        reality = try object.decode(Traffic.self, forKey: .reality)
        hy2 = try object.decode(Traffic.self, forKey: .hy2)
    }
}

/// Shares per protocol, in basis points (10 000 is the whole).
public struct ProtocolShares: Decodable, Hashable, Sendable {
    public let reality: UInt16
    public let hy2: UInt16

    enum CodingKeys: String, CodingKey, CaseIterable {
        case reality, hy2
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        reality = try object.decode(UInt16.self, forKey: .reality)
        hy2 = try object.decode(UInt16.self, forKey: .hy2)
    }
}

/// A user's shares of the cycle's served bytes, by node and by protocol,
/// in basis points.
public struct CycleShares: Decodable, Hashable, Sendable {
    public let byNode: [NodeId: UInt16]
    public let byProtocol: ProtocolShares

    enum CodingKeys: String, CodingKey, CaseIterable {
        case byNode = "by_node"
        case byProtocol = "by_protocol"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        byNode = try object.decode([NodeId: UInt16].self, forKey: .byNode)
        byProtocol = try object.decode(ProtocolShares.self, forKey: .byProtocol)
    }
}

/// A user's usage over the report's periods.
public struct UserUsage: Decodable, Hashable, Sendable {
    public let today: Traffic
    public let cycle: Traffic
    public let month: Traffic
    public let lifetime: Traffic
    public let cycleServedBytes: UInt64
    public let cycleByNode: [NodeId: Traffic]
    public let cycleByProtocol: ProtocolTraffic
    /// `nil` when the user used nothing this cycle.
    public let cycleShares: CycleShares?

    enum CodingKeys: String, CodingKey, CaseIterable {
        case today, cycle, month, lifetime
        case cycleServedBytes = "cycle_served_bytes"
        case cycleByNode = "cycle_by_node"
        case cycleByProtocol = "cycle_by_protocol"
        case cycleShares = "cycle_shares"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        today = try object.decode(Traffic.self, forKey: .today)
        cycle = try object.decode(Traffic.self, forKey: .cycle)
        month = try object.decode(Traffic.self, forKey: .month)
        lifetime = try object.decode(Traffic.self, forKey: .lifetime)
        cycleServedBytes = try object.decode(UInt64.self, forKey: .cycleServedBytes)
        cycleByNode = try object.decode([NodeId: Traffic].self, forKey: .cycleByNode)
        cycleByProtocol = try object.decode(ProtocolTraffic.self, forKey: .cycleByProtocol)
        cycleShares = try object.decodeNullable(CycleShares.self, forKey: .cycleShares)
    }
}

/// A user's quota this cycle.
public enum QuotaState: Decodable, Hashable, Sendable {
    case noQuota
    case within(usedBytes: UInt64, quotaBytes: UInt64)
    case warn(usedBytes: UInt64, quotaBytes: UInt64)
    case over(usedBytes: UInt64, quotaBytes: UInt64)
    /// The quota's use cannot be judged without usage figures.
    case usageUnavailable(quotaBytes: UInt64)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("no_quota", nil): self = .noQuota
        case ("within", let value?):
            let (used, quota) = try Self.figures(value)
            self = .within(usedBytes: used, quotaBytes: quota)
        case ("warn", let value?):
            let (used, quota) = try Self.figures(value)
            self = .warn(usedBytes: used, quotaBytes: quota)
        case ("over", let value?):
            let (used, quota) = try Self.figures(value)
            self = .over(usedBytes: used, quotaBytes: quota)
        case ("usage_unavailable", let value?):
            self = .usageUnavailable(
                quotaBytes: try value.fields("quota_bytes").field(UInt64.self, "quota_bytes"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }

    private static func figures(_ value: any Decoder) throws -> (UInt64, UInt64) {
        let object = try value.fields("used_bytes", "quota_bytes")
        return (
            try object.field(UInt64.self, "used_bytes"), try object.field(UInt64.self, "quota_bytes")
        )
    }
}

/// A user's expiry.
public enum ExpiryState: Decodable, Hashable, Sendable {
    case noExpiry
    case expires(at: UnixTime, daysLeft: UInt64)
    case expired(at: UnixTime)

    public init(from decoder: any Decoder) throws {
        let (tag, value) = try decoder.variant()
        switch (tag, value) {
        case ("no_expiry", nil): self = .noExpiry
        case ("expires", let value?):
            let object = try value.fields("at", "days_left")
            self = .expires(
                at: try object.field(UnixTime.self, "at"),
                daysLeft: try object.field(UInt64.self, "days_left"))
        case ("expired", let value?):
            self = .expired(at: try value.fields("at").field(UnixTime.self, "at"))
        default:
            throw decoder.unknownVariant(tag)
        }
    }
}

/// What limits a row's accuracy (design §15.4).
public struct UsageAccuracy: Decodable, Hashable, Sendable {
    /// REALITY downloads are counted when their connection closes.
    public let realityDownlinkCountedAtClose: Bool

    enum CodingKeys: String, CodingKey, CaseIterable {
        case realityDownlinkCountedAtClose = "reality_downlink_counted_at_close"
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        realityDownlinkCountedAtClose = try object.decode(
            Bool.self, forKey: .realityDownlinkCountedAtClose)
    }
}

/// One user.
public struct UserRow: Decodable, Hashable, Sendable {
    /// The public alias, if one was issued.
    public let alias: String?
    public let status: UserStatus
    /// The nodes holding the user's credentials.
    public let nodes: [NodeId]
    public let activity: UserActivity
    /// Usage, when the status's usage view is a report.
    public let usage: UserUsage?
    public let quota: QuotaState
    public let expiry: ExpiryState
    public let accuracy: UsageAccuracy

    enum CodingKeys: String, CodingKey, CaseIterable {
        case alias, status, nodes, activity, usage, quota, expiry, accuracy
    }

    public init(from decoder: any Decoder) throws {
        let object = try decoder.strictContainer(keyedBy: CodingKeys.self)
        alias = try object.decodeNullable(String.self, forKey: .alias)
        status = try object.decode(UserStatus.self, forKey: .status)
        nodes = try object.decode([NodeId].self, forKey: .nodes)
        activity = try object.decode(UserActivity.self, forKey: .activity)
        usage = try object.decodeNullable(UserUsage.self, forKey: .usage)
        quota = try object.decode(QuotaState.self, forKey: .quota)
        expiry = try object.decode(ExpiryState.self, forKey: .expiry)
        accuracy = try object.decode(UsageAccuracy.self, forKey: .accuracy)
    }
}
