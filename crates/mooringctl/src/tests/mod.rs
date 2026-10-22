// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the command line (design §16 L1). The router commands run
//! against an in-process HTTP stub on `127.0.0.1`, reached through the
//! real `lo0` with `IP_BOUND_IF`; the kernel tables, the keychain, the
//! terminal and the clock are fakes. Nothing here contacts the M7 or any
//! other host, and the live keychain is never touched.

mod add;
mod capture;
mod daemon;
mod export;
mod flow;
mod form;
mod http;
mod output;
mod password;
mod pin;
mod stub;
mod support;
mod units;
mod user;
