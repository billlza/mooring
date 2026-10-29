// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's own networks (design §10.2, P0-2): connections the
//! operator contracts for (the phone's Personal Hotspot, home broadband),
//! declared on the Mac so that the exit keeps serving while the Mac is
//! joined to one, even when it holds the default route. Never an
//! institutional network: on campus Wi-Fi, eduroam or Janet the exit must
//! stay down.
//!
//! A declaration names the network by its [`RouterIdentity`] (the SSID is
//! hidden from the daemon) under a [`LocalLabel`] of the operator's. The
//! declarations are Mac-local: `mooring-store` keeps them beside
//! `state.json`, never in it, and nothing exports or reports them.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::ids::LocalLabel;
use crate::iface::RouterIdentity;
use crate::time::UnixTime;

/// Apple's Personal Hotspot always routes through 172.20.10.1 (the iPhone,
/// on 172.20.10.0/28).
pub const PERSONAL_HOTSPOT_ROUTER: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 1);

/// What kind of connection an own network is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnNetworkKind {
    /// The operator's own phone, as Apple's Personal Hotspot. Over Wi-Fi,
    /// USB and Bluetooth the phone shows another link-layer address each,
    /// so each medium is declared on its own.
    PersonalHotspot,
    /// A fixed line the operator contracts for, such as home broadband.
    Broadband,
}

/// One declared own network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnNetwork {
    /// Its kind.
    pub kind: OwnNetworkKind,
    /// The router that identifies it.
    pub router: RouterIdentity,
    /// When the operator declared it (the Mac's clock; informational).
    pub declared_at: UnixTime,
}

/// The declared own networks, by the operator's label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OwnNetworks(BTreeMap<LocalLabel, OwnNetwork>);

impl OwnNetworks {
    /// No declaration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares `network` under `name`, returning the declaration that held
    /// the name before, if any. The CLI refuses a name in use before it
    /// asks, so a replacement here comes from a file edited by hand.
    pub fn insert(&mut self, name: LocalLabel, network: OwnNetwork) -> Option<OwnNetwork> {
        self.0.insert(name, network)
    }

    /// Withdraws the declaration named `name`, if there is one.
    pub fn remove(&mut self, name: &LocalLabel) -> Option<OwnNetwork> {
        self.0.remove(name)
    }

    /// The declaration named `name`.
    #[must_use]
    pub fn get(&self, name: &LocalLabel) -> Option<&OwnNetwork> {
        self.0.get(name)
    }

    /// The declaration whose router is `router`: its address and its
    /// link-layer address must both match. The same router declared under
    /// two names matches the first by name.
    #[must_use]
    pub fn matching(&self, router: &RouterIdentity) -> Option<(&LocalLabel, &OwnNetwork)> {
        self.0.iter().find(|(_, network)| network.router == *router)
    }

    /// Every declaration, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&LocalLabel, &OwnNetwork)> {
        self.0.iter()
    }

    /// How many networks are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether none is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::MacAddr;

    fn router(addr: [u8; 4], lladdr: &str) -> RouterIdentity {
        RouterIdentity::new(Ipv4Addr::from(addr), MacAddr::parse(lladdr).unwrap()).unwrap()
    }

    fn label(text: &str) -> LocalLabel {
        LocalLabel::parse(text).unwrap()
    }

    fn network(kind: OwnNetworkKind, router: RouterIdentity) -> OwnNetwork {
        OwnNetwork {
            kind,
            router,
            declared_at: UnixTime::from_secs(1_793_300_000),
        }
    }

    #[test]
    fn own_networks_match_by_router_address_and_link_layer_address() {
        let hotspot = router([172, 20, 10, 1], "aa:bb:cc:dd:ee:01");
        let home = router([192, 168, 0, 1], "aa:bb:cc:dd:ee:02");
        let mut declared = OwnNetworks::new();
        assert!(declared.is_empty());
        assert_eq!(
            declared.insert(
                label("my phone"),
                network(OwnNetworkKind::PersonalHotspot, hotspot)
            ),
            None
        );
        assert_eq!(
            declared.insert(label("home"), network(OwnNetworkKind::Broadband, home)),
            None
        );
        assert_eq!(declared.len(), 2);
        assert_eq!(
            declared
                .matching(&hotspot)
                .map(|(name, network)| (name.as_str(), network.kind)),
            Some(("my phone", OwnNetworkKind::PersonalHotspot))
        );
        // The same address behind another device, and the same device at
        // another address, are other networks.
        assert_eq!(
            declared.matching(&router([172, 20, 10, 1], "aa:bb:cc:dd:ee:02")),
            None
        );
        assert_eq!(
            declared.matching(&router([172, 20, 10, 2], "aa:bb:cc:dd:ee:01")),
            None
        );
        assert_eq!(
            declared
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["home", "my phone"]
        );
        assert_eq!(
            declared.get(&label("home")).map(|network| network.router),
            Some(home)
        );
        assert_eq!(declared.remove(&label("nobody")), None);
        assert_eq!(
            declared
                .remove(&label("home"))
                .map(|network| network.router),
            Some(home)
        );
        assert_eq!(declared.matching(&home), None);
        // A name in use is replaced, and the replaced declaration returned.
        assert_eq!(
            declared
                .insert(label("my phone"), network(OwnNetworkKind::Broadband, home))
                .map(|network| network.router),
            Some(hotspot)
        );
        assert_eq!(declared.matching(&hotspot), None);
        assert_eq!(
            declared.matching(&home).map(|(name, _)| name.as_str()),
            Some("my phone")
        );
    }

    #[test]
    fn the_kind_encoding_and_the_hotspot_router_are_pinned() {
        assert_eq!(
            serde_json::to_string(&OwnNetworkKind::PersonalHotspot).unwrap(),
            r#""personal_hotspot""#
        );
        assert_eq!(
            serde_json::to_string(&OwnNetworkKind::Broadband).unwrap(),
            r#""broadband""#
        );
        assert_eq!(
            serde_json::from_str::<OwnNetworkKind>(r#""broadband""#).unwrap(),
            OwnNetworkKind::Broadband
        );
        assert!(serde_json::from_str::<OwnNetworkKind>(r#""campus""#).is_err());
        assert_eq!(PERSONAL_HOTSPOT_ROUTER, Ipv4Addr::new(172, 20, 10, 1));
    }
}
