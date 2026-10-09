// SPDX-License-Identifier: GPL-3.0-or-later

//! Automatic per-user quotas (design §15.3, decision F4, 2026-10-08).
//!
//! From [`AutoQuotaPolicy::from_active_users`] users sharing the cycle's
//! budget on, each user's cycle quota is a share of the cycle's served
//! budget divided among them; a user's own `UserPolicy::quota` overrides
//! it. The users sharing the budget are those `Active` now and those
//! suspended for quota during the current cycle (latched per cycle, decided
//! 2026-10-09). The served budget is the SIM budget
//! ([`crate::sim::SimThresholds::budget_bytes`]) divided by the recorded
//! [`SimFactor`]. This module holds the record; `daemon-core` computes the
//! quota from it.

use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;
use crate::user::{QuotaAction, WarnPercent};

/// A share of the cycle's served budget, 1..=100 percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct BudgetPercent(u8);

impl BudgetPercent {
    /// Accepts 1..=100.
    pub fn new(percent: u8) -> Result<Self, ModelError> {
        Self::checked(percent).ok_or(ModelError::InvalidBudgetPercent { percent })
    }

    /// The share `percent` if it is 1..=100; usable in constants.
    const fn checked(percent: u8) -> Option<Self> {
        if matches!(percent, 1..=100) {
            Some(Self(percent))
        } else {
            None
        }
    }

    /// The percentage.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for BudgetPercent {
    type Error = ModelError;

    fn try_from(percent: u8) -> Result<Self, Self::Error> {
        Self::new(percent)
    }
}

impl From<BudgetPercent> for u8 {
    fn from(percent: BudgetPercent) -> Self {
        percent.0
    }
}

/// SIM bytes per served byte, in thousandths, at least 1000: each served
/// byte crosses the SIM at least once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct SimFactor(u16);

impl SimFactor {
    /// Design §3's estimate for the `SameAsExit` uplink, about 2.1 SIM bytes
    /// per served byte, because what users download arrives over the SIM and
    /// leaves again through the tunnel on the same SIM. An inference until
    /// M8 measures the factor (SIM bytes divided by the sum of served bytes,
    /// design §15.4); the operator then records the measured one, and again
    /// after any change of uplink mode.
    pub const SAME_AS_EXIT_ESTIMATE: Self = match Self::checked(2100) {
        Some(factor) => factor,
        None => panic!("design §3's factor is at least 1000 permille"),
    };

    /// Accepts 1000 permille and more.
    pub fn new(permille: u16) -> Result<Self, ModelError> {
        Self::checked(permille).ok_or(ModelError::InvalidSimFactor { permille })
    }

    /// The factor `permille` if it is at least 1000; usable in constants.
    const fn checked(permille: u16) -> Option<Self> {
        if permille >= 1000 {
            Some(Self(permille))
        } else {
            None
        }
    }

    /// The factor, in thousandths.
    #[must_use]
    pub const fn permille(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for SimFactor {
    type Error = ModelError;

    fn try_from(permille: u16) -> Result<Self, Self::Error> {
        Self::new(permille)
    }
}

impl From<SimFactor> for u16 {
    fn from(factor: SimFactor) -> Self {
        factor.0
    }
}

/// Automatic per-user quotas (decision F4, 2026-10-08): while at least
/// `from_active_users` users share the cycle's budget, each user without an
/// override gets `budget_percent` of the cycle's served budget divided by
/// the number of users sharing it, warned at `warn_percent` of it and
/// handled by `action` at all of it. The users sharing it are those
/// `Active` now and those suspended with `SuspendReason::QuotaExceeded`
/// during the current cycle, at or after its start, whatever cycle start
/// the suspension records, so a suspension for quota never changes a share
/// within its cycle (latched per cycle, decided 2026-10-09).
///
/// No rule ties `from_active_users` to the cap on active users: with the
/// pilot's cap of 5 ([`crate::deployment::CapacityPolicy::PILOT`]) at most 5
/// users are active, fewer than [`AutoQuotaPolicy::PILOT`]'s 6, so the
/// automatic quotas stay dormant until the operator raises the cap, unless
/// users suspended for their own quota in the current cycle bring the count
/// to 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoQuotaPolicy {
    /// Automatic quotas apply while at least this many users share the
    /// cycle's budget: `Active`, or suspended for quota in the current
    /// cycle (F4: 6).
    pub from_active_users: NonZeroU16,
    /// The share of the cycle's served budget the users sharing it divide
    /// (F4: 80).
    pub budget_percent: BudgetPercent,
    /// SIM bytes per served byte; turns the SIM budget into a served budget.
    pub sim_factor: SimFactor,
    /// The share of a quota at which the operator is warned (F4: 80).
    pub warn_percent: WarnPercent,
    /// What reaching the quota does (F4: a reversible suspension,
    /// `SuspendReason::QuotaExceeded`).
    pub action: QuotaAction,
}

impl AutoQuotaPolicy {
    /// Decision F4 as `exit init` records it: from 6 users sharing the
    /// budget, 80 % of the served budget divided among them, at design §3's
    /// SIM factor, a warning at 80 % of a quota and a suspension at all of
    /// it.
    pub const PILOT: Self = Self {
        from_active_users: match NonZeroU16::new(6) {
            Some(users) => users,
            None => panic!("F4's threshold is not zero"),
        },
        budget_percent: match BudgetPercent::checked(80) {
            Some(percent) => percent,
            None => panic!("F4's budget share is 1..=100"),
        },
        sim_factor: SimFactor::SAME_AS_EXIT_ESTIMATE,
        warn_percent: match WarnPercent::checked(80) {
            Some(percent) => percent,
            None => panic!("F4's warning share is 1..=99"),
        },
        action: QuotaAction::Suspend,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pilot_policy_is_the_f4_decision() {
        let pilot = AutoQuotaPolicy::PILOT;
        assert_eq!(pilot.from_active_users.get(), 6);
        assert_eq!(pilot.budget_percent.get(), 80);
        assert_eq!(pilot.sim_factor.permille(), 2100);
        assert_eq!(pilot.sim_factor, SimFactor::SAME_AS_EXIT_ESTIMATE);
        assert_eq!(pilot.warn_percent.get(), 80);
        assert_eq!(pilot.action, QuotaAction::Suspend);
    }

    #[test]
    fn budget_percents_encode_as_numbers() {
        for bad in [0, 101, 255] {
            assert_eq!(
                BudgetPercent::new(bad),
                Err(ModelError::InvalidBudgetPercent { percent: bad })
            );
            assert!(serde_json::from_str::<BudgetPercent>(&bad.to_string()).is_err());
        }
        for good in [1, 80, 100] {
            let percent = BudgetPercent::new(good).unwrap();
            assert_eq!(percent.get(), good);
            assert_eq!(serde_json::to_string(&percent).unwrap(), good.to_string());
            assert_eq!(
                serde_json::from_str::<BudgetPercent>(&good.to_string()).unwrap(),
                percent
            );
        }
    }

    #[test]
    fn sim_factors_encode_as_numbers() {
        for bad in [0, 1, 999] {
            assert_eq!(
                SimFactor::new(bad),
                Err(ModelError::InvalidSimFactor { permille: bad })
            );
            assert!(serde_json::from_str::<SimFactor>(&bad.to_string()).is_err());
        }
        for good in [1000, 1040, 2100, u16::MAX] {
            let factor = SimFactor::new(good).unwrap();
            assert_eq!(factor.permille(), good);
            assert_eq!(serde_json::to_string(&factor).unwrap(), good.to_string());
            assert_eq!(
                serde_json::from_str::<SimFactor>(&good.to_string()).unwrap(),
                factor
            );
        }
        assert!(serde_json::from_str::<SimFactor>("65536").is_err());
    }

    /// The record's exact encoding; every key is required and no other is
    /// accepted.
    #[test]
    fn the_auto_quota_record_has_a_fixed_encoding() {
        let json = r#"{"from_active_users":6,"budget_percent":80,"sim_factor":2100,"warn_percent":80,"action":"suspend"}"#;
        assert_eq!(
            serde_json::to_string(&AutoQuotaPolicy::PILOT).unwrap(),
            json
        );
        assert_eq!(
            serde_json::from_str::<AutoQuotaPolicy>(json).unwrap(),
            AutoQuotaPolicy::PILOT
        );
        for key in [
            r#""from_active_users":6,"#,
            r#""budget_percent":80,"#,
            r#""sim_factor":2100,"#,
            r#""warn_percent":80,"#,
            r#","action":"suspend""#,
        ] {
            let missing = json.replacen(key, "", 1);
            assert_ne!(missing, json);
            assert!(
                serde_json::from_str::<AutoQuotaPolicy>(&missing).is_err(),
                "{missing}"
            );
        }
        for bad in [
            json.replacen('{', r#"{"zz_unknown":true,"#, 1),
            json.replace(r#""from_active_users":6"#, r#""from_active_users":0"#),
            json.replace(r#""budget_percent":80"#, r#""budget_percent":101"#),
            json.replace(r#""sim_factor":2100"#, r#""sim_factor":999"#),
            json.replace(r#""warn_percent":80"#, r#""warn_percent":100"#),
            json.replace(r#""action":"suspend""#, r#""action":"revoke""#),
        ] {
            assert_ne!(bad, json);
            assert!(
                serde_json::from_str::<AutoQuotaPolicy>(&bad).is_err(),
                "{bad}"
            );
        }
        let warning = json.replace(r#""action":"suspend""#, r#""action":"warn""#);
        assert_eq!(
            serde_json::from_str::<AutoQuotaPolicy>(&warning)
                .unwrap()
                .action,
            QuotaAction::Warn
        );
    }

    /// Every `u8`: exactly 1..=100 is a budget share.
    #[test]
    fn budget_percent_bounds() {
        for percent in u8::MIN..=u8::MAX {
            assert_eq!(
                BudgetPercent::new(percent).is_ok(),
                (1..=100).contains(&percent),
                "{percent}"
            );
        }
    }

    /// Every `u16`: exactly 1000 permille and more is a SIM factor.
    #[test]
    fn sim_factor_bounds() {
        for permille in u16::MIN..=u16::MAX {
            assert_eq!(
                SimFactor::new(permille).is_ok(),
                permille >= 1000,
                "{permille}"
            );
        }
    }
}
