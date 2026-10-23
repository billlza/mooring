// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's runtime on the Mac (design §10.1, §10.2): resolving the
//! exit's interfaces, the foreign-network snapshot, probing a node's
//! reflector through the egress, running the engine, the SIM meter's
//! thread, the power helper, and the exit machine's ports over all of
//! them. The daemon drives them.

pub(crate) mod engine;
pub(crate) mod meter;
pub(crate) mod network;
pub(crate) mod ports;
pub(crate) mod power;
pub(crate) mod probe;
pub(crate) mod resolve;
