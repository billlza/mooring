// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the kernel interfaces (design §16 L1): routing, neighbour and
//! interface-list messages built byte by byte, the live tables of this Mac
//! checked against the system's own tools, the open-files limit, and the
//! echo guard on a pseudo-terminal. None needs root, and none sends a
//! packet except one datagram on lo0, to see its counter move.

mod configd;
mod errors;
mod iflist;
mod limits;
mod live;
mod messages;
mod process;
mod terminal;
