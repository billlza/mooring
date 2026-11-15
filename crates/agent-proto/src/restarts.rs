// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether a transaction may restart what serves users, and what a change
//! would restart (design §11.2 steps 2 and 5, §13.6; protocol 3).

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;

closed_enum! {
    /// Whether the transaction an `Apply` launches may restart what serves
    /// users.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Restarts {
        /// Only a change the running engines take as they run: clients added
        /// to the running Xray, and files their readers read again (the
        /// watch's configuration, the viewers' keys). Anything else is
        /// refused before anything is switched
        /// ([`crate::AgentError::RestartNotAllowed`]), and a change applied
        /// so is undone as it was made, through Xray's API, by whatever
        /// undoes it. A node's first generation is exempt: nothing is served
        /// before it, so nothing can drop.
        Refused,
        /// Whatever the change needs is restarted, as every `Apply` was
        /// before protocol 3.
        Allowed,
    }
}

closed_enum! {
    /// What a change would restart or reload that serves users, in the order
    /// a transaction applies it (design §11.2 step 5).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum RestartNeed {
        /// The ruleset changed: `nft -f`, which leaves the gate closed until
        /// the watch reopens it.
        Nftables,
        /// The tunnel's configuration changed: a restart of
        /// `wg-quick@wgexit`, or its peers synchronised.
        WireGuard,
        /// A host-profile file changed: what it needs runs (a unit restarted,
        /// journald restarted, sshd reloaded).
        HostProfile,
        /// The engine set changed: both engines restart.
        Engines,
        /// Xray's configuration changed otherwise than by clients added to
        /// its two VLESS inbounds, or the running generation's cannot be read.
        XrayConfig,
        /// The running generation's Xray serves no `HandlerService` on the
        /// rendered API listener, so it cannot take clients as it runs.
        XrayApi,
        /// Xray is not running (`systemctl is-active` does not print
        /// `active`), so it cannot take clients as it runs.
        XrayStopped,
        /// Hysteria 2's configuration changed.
        Hy2Config,
    }
}
