// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the command line (design §16 L1). The router commands run
//! against an in-process HTTP stub on `127.0.0.1`, reached through the
//! real `lo0` with `IP_BOUND_IF`; the kernel tables, the keychain, the
//! terminal and the clock are fakes. Nothing here contacts the M7 or any
//! other host, and the live keychain is never touched.

mod add;
mod adopt;
mod answered;
mod app;
mod apply;
mod canary;
mod cancel;
mod capture;
mod console;
mod control;
mod daemon;
mod debug;
mod deployed;
mod engine;
mod engine_pins;
mod errors;
mod exit;
mod export;
mod flow;
mod form;
mod history;
mod http;
mod log;
mod meter;
mod node;
mod node_files;
mod output;
mod own_network;
mod password;
mod payments;
mod pin;
mod portal;
mod ports;
mod power;
mod probe;
mod profiles;
mod relay_failures;
mod repin;
mod router;
mod runtime;
mod sockopt;
mod ssh;
mod status;
mod stub;
mod support;
mod target;
mod ticks;
mod transaction;
mod units;
mod upgrade;
mod usage_collection;
mod user;
mod user_usage;
