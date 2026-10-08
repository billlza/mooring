// SPDX-License-Identifier: GPL-3.0-or-later

//! Pieces shared by the three sing-box 1.14.2 configs: `hy2.json` on the
//! VPS, and `mooring-exit` and `mooring-probe` on the Mac.

use mooring_model::iface::BsdName;
use serde::{Deserialize, Serialize};

use crate::literal::literal;

literal!(
    /// The only log level the renderer writes (`option/options.go:71`,
    /// `log/level.go:52-53`). Every engine logs destinations at INFO, so the
    /// type has no info or debug value; validation uses separate warn-level
    /// copies (design §11.2).
    LogLevel = "fatal"
);

/// `log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Log {
    pub(crate) level: LogLevel,
}

literal!(
    /// A route rule's `route` action (`option/rule_action.go:19,174-176`).
    RouteAction = "route"
);

literal!(
    /// A route rule's `reject` action (`option/rule_action.go:19`).
    RejectAction = "reject"
);

literal!(
    /// The `tcp` network of a rule or a `direct` inbound (`option/types.go:20-40`).
    Tcp = "tcp"
);

literal!(
    /// The `direct` inbound and outbound type.
    DirectType = "direct"
);

/// `bind_interface` (`option/outbound.go:86`, embedded by every outbound
/// and by the WireGuard endpoint, `option/wireguard.go:22`). Every Mac-side
/// outbound and endpoint has one, so no Mac socket follows the default route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct BindInterface(BsdName);

impl BindInterface {
    pub(crate) const fn new(name: BsdName) -> Self {
        Self(name)
    }

    #[cfg(test)]
    pub(crate) const fn name(&self) -> &BsdName {
        &self.0
    }
}
