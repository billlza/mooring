// SPDX-License-Identifier: GPL-3.0-or-later

//! macOS kernel interfaces for Mooring (design §6, §6.1), the only crate
//! with `unsafe` code (libc only):
//!
//! - [`interface_index`]: a BSD interface name's index (`if_nametoindex`);
//! - [`default_gateway_v4`]: an interface's one IPv4 default gateway, from
//!   the kernel's routing table (`sysctl` PF_ROUTE `NET_RT_DUMP`), scoped
//!   (`RTF_IFSCOPE`) and unscoped routes alike;
//! - [`neighbour_v4`]: that gateway's link-layer address on the interface,
//!   from the IPv4 neighbour (ARP) table (`NET_RT_FLAGS` with
//!   `RTF_LLINFO`), which is the M7's identity (design §15.6 rule 4); a
//!   dump of no bytes is reported as just that,
//!   [`MacsysError::NeighbourTableEmpty`], and whether the kernel hid the
//!   table from this process is the caller's judgement (design §15.6
//!   rule 10);
//! - [`controlling_terminal`] and [`EchoOff`]: the process's terminal, and
//!   its echo switched off while a password is typed.
//!
//! Nothing here shells out (no `arp`, `netstat` or `route`). The routing
//! messages are parsed from the bytes the kernel returns by safe code that
//! checks every length against the buffer; `unsafe` is confined to the
//! system calls themselves, one call per block.
//!
//! The crate has no workspace dependency: it returns std types
//! (`NonZeroU32`, `Ipv4Addr`, `[u8; 6]`), which `mooringctl` turns into the
//! model's `InterfaceIndex` and `MacAddr`.
//!
//! macOS only: on any other target the crate is empty, so the workspace
//! builds and its gates run on the ubuntu L0 lane (design §16).

#![cfg(target_os = "macos")]
#![deny(missing_docs)]

mod error;
mod interface;
mod route;
mod terminal;
#[cfg(test)]
mod tests;

pub use error::{MacsysError, MacsysErrorKind, RouteFault, TerminalCall};
pub use interface::interface_index;
pub use route::{default_gateway_v4, neighbour_v4};
pub use terminal::{EchoOff, controlling_terminal};
