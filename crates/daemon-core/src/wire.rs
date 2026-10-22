// SPDX-License-Identifier: GPL-3.0-or-later

//! The conversions between the model's types and agent-proto's wire types
//! that the console core makes, all in one place (design §6.1). `render`
//! owns the conversions that build what a node is sent
//! (`crates/render/src/wire.rs`); these read what a node reports.
//!
//! - An instant: both protocols count whole seconds since the Unix epoch,
//!   so the conversion is exact, both ways.
//! - An accounting principal: the renderer writes a user's accounting name
//!   as the user's id (render `Identity::email`, `OpaqueUserId::new` of
//!   `UserId::as_str`), so reading it back is parsing that id; the probe
//!   has its own principal, and `probe` is no opaque id, so it is never a
//!   user.
//! - The remote viewer's report (decision F5) names a user by
//!   `ReportUserId` and a node by `NodeName`, whose rules are exactly the
//!   model's `UserId` and `NodeId` rules (render's wire-rule tests compare
//!   them), so every model id converts; the conversion still checks.
//! - A radio band's number: `ReportBandNumber` is exactly the router's
//!   [`BandNumber`] rule, 1..=999 (compared value by value below), so every
//!   band converts; the conversion still checks.
//! - An alert's kind: `MacAlertKind` spells the console's
//!   [`AlertConditionKind`] names, matched exhaustively here.
//! - The router's data service: `ReportDataService` has one variant per
//!   [`DataService`], of the same meaning, matched exhaustively here.

use mooring_agent_proto::{
    MacAlertKind, NodeName, OpaqueUserId, ReportBandNumber, ReportDataService, ReportUserId,
    UnixTime as WireTime, ValueError,
};
use mooring_model::{ModelError, NodeId, UnixTime, UserId};

use crate::alert::AlertConditionKind;
use crate::router::{BandNumber, DataService};

/// The Mac's form of an instant the VPS reported.
#[must_use]
pub(crate) const fn mac_time(time: WireTime) -> UnixTime {
    UnixTime::from_secs(time.as_secs())
}

/// The wire form of an instant on the Mac.
#[must_use]
pub(crate) const fn wire_time(time: UnixTime) -> WireTime {
    WireTime::from_secs(time.as_secs())
}

/// The report's form of a user id.
pub(crate) fn report_user(user: &UserId) -> Result<ReportUserId, ValueError> {
    ReportUserId::new(user.as_str())
}

/// The report's form of a node id.
pub(crate) fn node_name(node: &NodeId) -> Result<NodeName, ValueError> {
    NodeName::new(node.as_str())
}

/// The report's form of a band number.
pub(crate) const fn report_band_number(number: BandNumber) -> Result<ReportBandNumber, ValueError> {
    ReportBandNumber::new(number.get())
}

/// The report's data service: the one of the same meaning. The match names
/// every service, so a service added on the Mac fails to compile until it
/// is mapped.
#[must_use]
pub(crate) const fn report_data_service(service: DataService) -> ReportDataService {
    match service {
        DataService::NrSub6 => ReportDataService::NrSub6,
        DataService::Lte => ReportDataService::Lte,
        DataService::LtePlus => ReportDataService::LtePlus,
    }
}

/// The report's name of an alert kind: the same name. The match names
/// every kind, so a kind added on either side fails to compile until it is
/// mapped.
#[must_use]
pub(crate) const fn mac_alert_kind(kind: AlertConditionKind) -> MacAlertKind {
    use AlertConditionKind as K;
    match kind {
        K::ExitViolation => MacAlertKind::ExitViolation,
        K::SimCapReached => MacAlertKind::SimCapReached,
        K::RouterOffloadActive => MacAlertKind::RouterOffloadActive,
        K::RouterWifiRadioOn => MacAlertKind::RouterWifiRadioOn,
        K::RouterOverheating => MacAlertKind::RouterOverheating,
        K::RouterRestarted => MacAlertKind::RouterRestarted,
        K::NodeHalted => MacAlertKind::NodeHalted,
        K::RollbackFailed => MacAlertKind::RollbackFailed,
        K::GateCloseFailed => MacAlertKind::GateCloseFailed,
        K::EngineCrashLoop => MacAlertKind::EngineCrashLoop,
        K::HostKeyMismatch => MacAlertKind::HostKeyMismatch,
        K::MacSilent => MacAlertKind::MacSilent,
        K::NodeUnreachable => MacAlertKind::NodeUnreachable,
        K::NodeDiskLow => MacAlertKind::NodeDiskLow,
        K::SimWarn => MacAlertKind::SimWarn,
        K::SimForecastCrossing => MacAlertKind::SimForecastCrossing,
        K::ExitDegraded => MacAlertKind::ExitDegraded,
        K::ForeignNetworkAttached => MacAlertKind::ForeignNetworkAttached,
        K::ReachabilitySuspect => MacAlertKind::ReachabilitySuspect,
        K::TargetDegraded => MacAlertKind::TargetDegraded,
        K::RouterNoService => MacAlertKind::RouterNoService,
        K::RouterOnLte => MacAlertKind::RouterOnLte,
        K::RouterThermalStepDown => MacAlertKind::RouterThermalStepDown,
        K::RouterWeakSignal => MacAlertKind::RouterWeakSignal,
        K::RouterFirmwareChanged => MacAlertKind::RouterFirmwareChanged,
        K::RouterUnreadSms => MacAlertKind::RouterUnreadSms,
        K::RouterCounterMismatch => MacAlertKind::RouterCounterMismatch,
        K::UsersNearQuota => MacAlertKind::UsersNearQuota,
        K::UsersOverQuota => MacAlertKind::UsersOverQuota,
        K::UsersSuspended => MacAlertKind::UsersSuspended,
        K::UsersExpiringSoon => MacAlertKind::UsersExpiringSoon,
        K::UsersExpired => MacAlertKind::UsersExpired,
        K::CapacitySaturated => MacAlertKind::CapacitySaturated,
        K::ExitFlowCapHit => MacAlertKind::ExitFlowCapHit,
        K::NodeClockUnsynced => MacAlertKind::NodeClockUnsynced,
        K::NodeRebootPending => MacAlertKind::NodeRebootPending,
        K::PendingApply => MacAlertKind::PendingApply,
        K::OperatorHoldLong => MacAlertKind::OperatorHoldLong,
        K::AccountingCanaryMissing => MacAlertKind::AccountingCanaryMissing,
    }
}

/// The user an accounting principal names: the inverse of the renderer's
/// accounting name. `InvalidUserId` for a name Mooring never renders.
pub(crate) fn accounting_user(principal: &OpaqueUserId) -> Result<UserId, ModelError> {
    UserId::parse(principal.as_str())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mooring_agent_proto::{Inbound, Principal, StatsEmail};
    use proptest::prelude::*;

    use super::*;

    /// The router's band number and the report's accept exactly the same
    /// numbers, every `u16` checked, and every band converts unchanged.
    #[test]
    fn band_number_rules_agree_at_every_value() {
        for number in 0..=u16::MAX {
            let router = BandNumber::new(number);
            assert_eq!(
                router.is_ok(),
                ReportBandNumber::new(number).is_ok(),
                "{number}"
            );
            if let Ok(router) = router {
                assert_eq!(report_band_number(router).unwrap().get(), number);
            }
        }
    }

    /// Each console kind maps to the report kind of the same name, and the
    /// two lists are the same length, so the map is a bijection.
    #[test]
    fn alert_kinds_map_to_the_report_kind_of_the_same_name() {
        assert_eq!(AlertConditionKind::ALL.len(), MacAlertKind::ALL.len());
        let mut mapped = BTreeSet::new();
        for &kind in AlertConditionKind::ALL {
            let wire = mac_alert_kind(kind);
            assert_eq!(wire.name(), kind.name());
            assert_eq!(
                serde_json::to_string(&wire).unwrap(),
                format!("\"{}\"", kind.name())
            );
            assert!(mapped.insert(wire), "{kind} maps onto a taken kind");
        }
        assert_eq!(mapped.len(), MacAlertKind::ALL.len());
    }

    /// Each data service maps to the report service of the same meaning
    /// (its variant name), and the two lists are the same length, so the
    /// map is a bijection.
    #[test]
    fn data_services_map_to_the_report_service_of_the_same_meaning() {
        assert_eq!(DataService::ALL.len(), ReportDataService::ALL.len());
        let mut mapped = BTreeSet::new();
        for &service in DataService::ALL {
            let wire = report_data_service(service);
            assert_eq!(format!("{service:?}"), wire.name());
            assert!(mapped.insert(wire), "{service:?} maps onto a taken service");
        }
        assert_eq!(mapped.len(), ReportDataService::ALL.len());
        assert_eq!(
            report_data_service(DataService::NrSub6),
            ReportDataService::NrSub6
        );
    }

    #[test]
    fn the_probe_is_never_a_user() {
        assert!(OpaqueUserId::new("probe").is_err());
        for inbound in Inbound::ALL {
            let email: StatsEmail = format!("probe@{}", inbound.as_str()).parse().unwrap();
            assert_eq!(email.principal, Principal::Probe);
        }
        // A name Mooring never renders reads as no user.
        let stranger = OpaqueUserId::new("u01").unwrap();
        assert_eq!(accounting_user(&stranger), Err(ModelError::InvalidUserId));
    }

    proptest! {
        /// Every user id survives the trip a node's accounting makes: the
        /// renderer's accounting name, its email on either inbound as the
        /// agent reports it, and back.
        #[test]
        fn every_user_id_comes_back_from_its_accounting_name(bits in any::<u64>(), reality in any::<bool>()) {
            let user = UserId::from_low_bits(bits);
            let principal = OpaqueUserId::new(user.as_str()).unwrap();
            prop_assert_eq!(accounting_user(&principal), Ok(user.clone()));
            let inbound = if reality { Inbound::Reality } else { Inbound::Hy2 };
            let email = StatsEmail { principal: Principal::User(principal), inbound };
            let reported: StatsEmail = email.to_string().parse().unwrap();
            let Principal::User(read) = reported.principal else {
                return Err(TestCaseError::fail("a user's email read back as the probe"));
            };
            prop_assert_eq!(accounting_user(&read), Ok(user));
        }

        #[test]
        fn instants_convert_exactly(secs in any::<u64>()) {
            prop_assert_eq!(mac_time(WireTime::from_secs(secs)).as_secs(), secs);
            prop_assert_eq!(wire_time(UnixTime::from_secs(secs)).as_secs(), secs);
        }

        /// Every user id and every node id has its report form, spelled
        /// the same.
        #[test]
        fn every_model_id_has_its_report_form(bits in any::<u64>(), node in "[a-z][a-z0-9]{1,11}") {
            let user = UserId::from_low_bits(bits);
            let reported = report_user(&user).unwrap();
            prop_assert_eq!(reported.as_str(), user.as_str());
            let node = NodeId::parse(&node).unwrap();
            let named = node_name(&node).unwrap();
            prop_assert_eq!(named.as_str(), node.as_str());
        }
    }
}
