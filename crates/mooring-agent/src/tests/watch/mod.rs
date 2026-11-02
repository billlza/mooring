// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch loop (design §11.3) against the stand-in node of [`world`],
//! whose WireGuard peer, gate set, counters, filesystem, chrony, engine
//! units and Xray API a test sets, and the events it journals (design
//! §15.7). Each part of a tick has a file of its own, as do what ends the
//! watch and the readers it reads with.

mod accounting;
mod conditions;
mod ending;
mod gating;
mod holds;
mod journaling;
mod readers;
mod status;
mod world;
