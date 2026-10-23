// SPDX-License-Identifier: GPL-3.0-or-later

//! The names the VPS side is built from (design §5.2, §8.4, §8.5, §11.3).
//!
//! The renderer writes these into the files it renders (`wgexit.conf`,
//! `nftables.conf`, `xray.json`) and the agent finds and acts on the same
//! names: the watch opens and closes the gate set, reads `wg show` and the
//! flow-cap counter, and the health gate checks the owner guard and the
//! interface. This module is the one definition both use, so neither side
//! can rename one without the other.

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;

/// The kernel WireGuard interface (`wg-quick@wgexit`). Xray's `exit`
/// outbound binds to it, the gate set lists it, and `wg show` reads it.
pub const WG_INTERFACE: &str = "wgexit";

/// The nftables table, family `inet`, that holds the whole ruleset.
pub const NFT_TABLE: &str = "mooring";

/// The nftables set of interface names whose presence closes the gate:
/// [`WG_INTERFACE`] in the set means exit traffic is rejected. It is closed
/// at load, and only `mooring-watch` removes the element.
pub const NFT_GATE_SET: &str = "exit_closed";

/// The routing table holding the default route through [`WG_INTERFACE`].
pub const EXIT_ROUTE_TABLE: u16 = 77;

/// The priority of the `oif` rule that sends device-bound sockets to
/// [`EXIT_ROUTE_TABLE`].
pub const EXIT_RULE_PRIORITY: u16 = 10_000;

/// The viewer account's name, as a literal for `concat!` (see
/// [`VIEWER_ACCOUNT`]).
macro_rules! viewer_account {
    () => {
        "mooring-view"
    };
}

pub(crate) use viewer_account;

/// The unprivileged account a remote viewer logs in as (design §15.9,
/// decision F5, critique C-9). It owns no files; sshd's `Match` block in
/// the host profile's drop-in gives it a root-owned `authorized_keys` file
/// and forces `serve-ssh --role viewer` (see [`crate::HostProfile`]).
pub const VIEWER_ACCOUNT: &str = viewer_account!();

/// The `mooring-watch` unit's account (design §5.2): the only process that
/// opens the gate.
pub const WATCH_ACCOUNT: &str = "mooring-watch";

/// The group that reads the node's state (the watch's view and journal,
/// the holds, the halt marker, the transaction records, the usage files
/// and the Mac report): the primary group of [`WATCH_ACCOUNT`] and
/// [`VIEWER_ACCOUNT`], and of no one else.
pub const STATE_GROUP: &str = "mooring";

closed_enum! {
    /// A named counter in [`NFT_TABLE`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum NftCounter {
        /// Connections the owner guard refused to `mooring-xray`.
        XrayGuard,
        /// Connections the owner guard refused to `mooring-hy2`.
        Hy2Guard,
        /// New exit flows refused over the node-wide flow cap
        /// (`ExitFlowCapHit`).
        FlowCap,
        /// New exit flows Xray opened to the node's own reflector: the
        /// Mac's in-chain probes, which only the probe identity may route
        /// there. Its growth is the accounting canary's evidence that Xray
        /// dispatched a probe (`AccountingCanaryMissing`).
        ProbeFlows,
    }
}

impl NftCounter {
    /// The counter's name in the ruleset.
    pub const fn name(self) -> &'static str {
        match self {
            Self::XrayGuard => "xray_guard",
            Self::Hy2Guard => "hy2_guard",
            Self::FlowCap => "flow_cap",
            Self::ProbeFlows => "probe_flows",
        }
    }
}

closed_enum! {
    /// An engine's Unix user: its unit runs as it, and the owner guard
    /// matches the connections it originates by it (`meta skuid`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum EngineUser {
        /// `mooring-xray.service`.
        Xray,
        /// `mooring-hy2.service`.
        Hy2,
    }
}

impl EngineUser {
    /// The user name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Xray => "mooring-xray",
            Self::Hy2 => "mooring-hy2",
        }
    }

    /// The engine's program in a generation, `engines/<name>`, a link into
    /// the engine store (design §11.2 step 4).
    pub const fn program(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::Hy2 => "mooring-hy2",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{IfName, ManagedFile, UnitName};

    #[test]
    fn the_names_are_the_designed_ones_and_distinct() {
        assert_eq!(WG_INTERFACE, "wgexit");
        assert!(IfName::new(WG_INTERFACE).is_ok());
        assert_eq!(
            ManagedFile::WgConf.file_name(),
            format!("{WG_INTERFACE}.conf")
        );
        assert_eq!(
            ManagedFile::WgConf.path(),
            format!("/etc/wireguard/{WG_INTERFACE}.conf")
        );
        assert_eq!((NFT_TABLE, NFT_GATE_SET), ("mooring", "exit_closed"));
        assert_eq!((EXIT_ROUTE_TABLE, EXIT_RULE_PRIORITY), (77, 10_000));
        let counters: BTreeSet<&str> = NftCounter::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            counters,
            BTreeSet::from(["flow_cap", "hy2_guard", "probe_flows", "xray_guard"])
        );
        for user in EngineUser::ALL {
            assert!(UnitName::new(format!("{}.service", user.name())).is_ok());
        }
        let users: Vec<&str> = EngineUser::ALL.iter().map(|user| user.name()).collect();
        assert_eq!(users, ["mooring-xray", "mooring-hy2"]);
        assert_eq!(VIEWER_ACCOUNT, "mooring-view");
        assert_eq!((WATCH_ACCOUNT, STATE_GROUP), ("mooring-watch", "mooring"));
        let mut accounts = users.clone();
        accounts.extend([VIEWER_ACCOUNT, WATCH_ACCOUNT, STATE_GROUP]);
        accounts.sort_unstable();
        accounts.dedup();
        assert_eq!(accounts.len(), 5);
    }
}
