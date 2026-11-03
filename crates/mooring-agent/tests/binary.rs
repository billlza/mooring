// SPDX-License-Identifier: GPL-3.0-or-later

//! The built binary, run with no arguments: on Linux it answers with the
//! usage, elsewhere that it runs on Linux; exit 1 and nothing on stdout
//! either way. No command is ever passed here: a real one would act on
//! this host.

use std::process::{Command, Stdio};

#[test]
fn the_binary_with_no_arguments_exits_1_and_says_why() {
    let output = Command::new(env!("CARGO_BIN_EXE_mooring-agent"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let expected = if cfg!(target_os = "linux") {
        "mooring-agent: usage: mooring-agent serve-ssh --role <bootstrap|ops|viewer> | reflect [--port <port>] | halted-check | gate-close | self-test | txn <N> | txn-revert <N> | txn-recover | watch | target-watch\n"
    } else {
        "mooring-agent: mooring-agent runs on Linux (the VPS); this build is for its tests\n"
    };
    assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
}
