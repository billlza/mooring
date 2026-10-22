// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line, and the commands systemd runs: `halted-check`,
//! `gate-close` and `self-test`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::ExitCode;

use mooring_agent_proto::{Generation, Halt, Role, ShutdownReason, UnixTime};

use super::{FakeNode, failed, scratch};
use crate::agent::{Invocation, parse, run, self_test};
use crate::store::write_json;

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn the_commands_parse_as_the_units_and_keys_write_them() {
    for (role, text) in [
        (Role::Bootstrap, "bootstrap"),
        (Role::Ops, "ops"),
        (Role::Viewer, "viewer"),
    ] {
        assert_eq!(
            parse(&args(&["serve-ssh", "--role", text])),
            Ok(Invocation::ServeSsh(role))
        );
        assert!(
            role.forced_command()
                .ends_with(&format!("serve-ssh --role {text}"))
        );
    }
    assert_eq!(
        parse(&args(&["reflect", "--listen", "176.126.246.203"])),
        Ok(Invocation::Reflect(SocketAddrV4::new(
            Ipv4Addr::new(176, 126, 246, 203),
            27900
        )))
    );
    assert_eq!(
        parse(&args(&[
            "reflect",
            "--listen",
            "127.0.0.1",
            "--port",
            "4000"
        ])),
        Ok(Invocation::Reflect(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            4000
        )))
    );
    assert_eq!(parse(&args(&["halted-check"])), Ok(Invocation::HaltedCheck));
    assert_eq!(parse(&args(&["gate-close"])), Ok(Invocation::GateClose));
    assert_eq!(parse(&args(&["self-test"])), Ok(Invocation::SelfTest));
    assert_eq!(
        parse(&args(&["txn", "3"])),
        Ok(Invocation::Txn(Generation::new(3)))
    );
    assert_eq!(
        parse(&args(&["txn-revert", "12"])),
        Ok(Invocation::TxnRevert(Generation::new(12)))
    );
    assert_eq!(parse(&args(&["txn-recover"])), Ok(Invocation::TxnRecover));
    for bad in ["0", "-1", "+2", "x", ""] {
        assert!(parse(&args(&["txn", bad])).is_err(), "txn {bad:?}");
    }
    for bad in [
        &[][..],
        &["serve-ssh"],
        &["serve-ssh", "--role", "root"],
        &["serve-ssh", "--role", "ops", "extra"],
        &["txn-recover", "1"],
        &["reflect", "--listen", "::1"],
        &["reflect", "--listen", "1.2.3.4", "--port", "70000"],
        &["halted-check", "now"],
        &["apply"],
    ] {
        assert!(parse(&args(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn halted_check_exits_1_while_halted() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let mut stderr = Vec::new();
    assert_eq!(
        run(Invocation::HaltedCheck, &paths, &node, &mut stderr),
        ExitCode::SUCCESS
    );
    write_json(
        &paths.halted(),
        &Halt {
            at: UnixTime::from_secs(1),
            reason: ShutdownReason::Operator,
        },
        0o640,
    )
    .unwrap();
    assert_eq!(
        run(Invocation::HaltedCheck, &paths, &node, &mut stderr),
        ExitCode::from(1)
    );
    assert!(stderr.is_empty());
}

#[test]
fn gate_close_closes_and_reports_a_failure() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let mut stderr = Vec::new();
    assert_eq!(
        run(Invocation::GateClose, &paths, &node, &mut stderr),
        ExitCode::SUCCESS
    );
    assert_eq!(
        node.calls(),
        vec!["/usr/sbin/nft add element inet mooring exit_closed { \"wgexit\" }".to_owned()]
    );
    let broken = FakeNode::answering(0, Box::new(|_, _| Ok(failed(b"no table"))));
    assert_eq!(
        run(Invocation::GateClose, &paths, &broken, &mut stderr),
        ExitCode::from(1)
    );
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .starts_with("mooring-agent: closing the gate failed")
    );
}

#[test]
fn the_self_test_refuses_damaged_state() {
    let (_dir, paths) = scratch();
    self_test(&paths).unwrap();
    std::fs::create_dir_all(paths.gate_dir()).unwrap();
    std::fs::write(paths.holds(), "{").unwrap();
    assert!(self_test(&paths).is_err());
    let node = FakeNode::new(0);
    let mut stderr = Vec::new();
    assert_eq!(
        run(Invocation::SelfTest, &paths, &node, &mut stderr),
        ExitCode::from(1)
    );
}
