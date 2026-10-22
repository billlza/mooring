// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit nat-behaviour`: how the line's NAT maps and filters UDP, the
//! two properties that decide whether a peer behind another NAT can reach
//! the Mac without a relay (RFC 4787; measured by hand on 2026-10-22, M2.md).
//!
//! - **Mapping:** one socket asks echo port A and then port B for the
//!   source they saw. The same public port for both means the mapping does
//!   not depend on the destination port.
//! - **Filtering:** a fresh socket sends only to port A, then asks port A to
//!   answer from port B, which it never sent to. An answer from B means the
//!   NAT admits a port the Mac has not contacted on an address it has; no
//!   answer, while A's own answers arrive, means address-and-port-dependent
//!   filtering (a port-restricted cone).
//!
//! With one server address this cannot tell address-dependent filtering
//! from none at all; a second server would.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::FieldkitError;
use crate::net::{Bind, Nonces, echo_now, exchange};
use crate::output::Output;
use crate::wire::{EchoKind, EchoRequest};

/// How many times the other-port request is tried.
const TRIES: u8 = 3;

/// How the mapping behaves when only the destination port changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mapping {
    /// The same public address and port towards both ports.
    SameForBothPorts,
    /// A different public port (or address) towards the second port.
    ChangesWithPort,
}

/// Whether the NAT admits a port the Mac has not sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Filtering {
    /// An answer from the port not contacted arrived.
    AdmitsUncontactedPort,
    /// None arrived, while answers from the contacted port did.
    AdmitsOnlyContactedPort,
    /// Neither arrived: the line or the server lost everything.
    Inconclusive,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// The public address the server saw.
    pub(crate) public_ip: Ipv4Addr,
    /// The mapping behaviour.
    pub(crate) mapping: Mapping,
    /// The filtering behaviour.
    pub(crate) filtering: Filtering,
}

/// Measures mapping and filtering against echo ports `a` and `b` of one
/// server.
pub(crate) fn run(
    bind: &Bind,
    a: SocketAddrV4,
    b: SocketAddrV4,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let nonces = Nonces::new();
    let socket = bind.udp()?;
    let (to_a, _) = echo_now(&socket, a, &nonces)?;
    let (to_b, _) = echo_now(&socket, b, &nonces)?;
    let mapping = if to_a.observed == to_b.observed {
        Mapping::SameForBothPorts
    } else {
        Mapping::ChangesWithPort
    };
    let fresh = bind.udp()?;
    let mut contacted = false;
    let mut uncontacted = false;
    for _try in 0..TRIES {
        contacted |= match echo_now(&fresh, a, &nonces) {
            Ok(_) => true,
            Err(FieldkitError::Silent { .. }) => false,
            Err(error) => return Err(error),
        };
        let request = EchoRequest {
            kind: EchoKind::FromOtherPort,
            nonce: nonces.next(),
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        uncontacted |= exchange(&fresh, a, b, &request, 1, Duration::ZERO, deadline)?.is_some();
        if uncontacted {
            break;
        }
    }
    let filtering = match (uncontacted, contacted) {
        (true, _) => Filtering::AdmitsUncontactedPort,
        (false, true) => Filtering::AdmitsOnlyContactedPort,
        (false, false) => Filtering::Inconclusive,
    };
    let summary = Summary {
        measure: "nat-behaviour",
        interface: bind.name().to_owned(),
        public_ip: *to_a.observed.ip(),
        mapping,
        filtering,
    };
    output.record(&summary)?;
    Ok(summary)
}
