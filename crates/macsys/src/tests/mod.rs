// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the kernel interfaces (design §16 L1): routing and neighbour
//! messages built byte by byte, the live tables of this Mac checked
//! against the system's own tools, and the echo guard on a pseudo-terminal.
//! None needs root, and none sends a packet.

mod errors;
mod live;
mod messages;
mod terminal;
