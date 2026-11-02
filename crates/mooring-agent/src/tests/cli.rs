// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line, and the commands systemd runs: `halted-check`,
//! `gate-close`, `self-test`, `reflect`, `watch` and `target-watch`, each
//! with the process's streams the test gives it.

use std::ffi::OsString;
use std::io::{self, Cursor, Write};
use std::net::TcpListener;
use std::os::unix::ffi::OsStringExt;
use std::process::ExitCode;

use mooring_agent_proto::{
    ClearableHold, Generation, Halt, Holds, LineRequest, Response, Role, ShutdownReason, UnixTime,
    read_reply,
};

use super::serve::frame;
use super::{FakeNode, failed, ok, scratch};
use crate::agent::{Invocation, Process, entry, parse, run, self_test};
use crate::host::Tool;
use crate::paths::Paths;
use crate::store::write_json;

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// What a command printed, and how it ended.
#[derive(Debug)]
pub(super) struct Ran {
    pub(super) code: ExitCode,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: String,
}

/// Runs `invocation` with `stdin` as its standard input and no
/// `SSH_CONNECTION`.
pub(super) fn ran(invocation: Invocation, paths: &Paths, node: &FakeNode, stdin: &[u8]) -> Ran {
    let mut input = Cursor::new(stdin.to_vec());
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = run(
        invocation,
        paths,
        node,
        &mut Process {
            ssh_connection: None,
            stdin: &mut input,
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    Ran {
        code,
        stdout,
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// A standard output that refuses every write, as a closed pipe does.
struct Refusing;

impl Write for Refusing {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Runs `invocation` with a standard output that refuses every write.
fn refused(invocation: Invocation, paths: &Paths, node: &FakeNode, stdin: &[u8]) -> Ran {
    let mut input = Cursor::new(stdin.to_vec());
    let mut stderr = Vec::new();
    let code = run(
        invocation,
        paths,
        node,
        &mut Process {
            ssh_connection: None,
            stdin: &mut input,
            stdout: &mut Refusing,
            stderr: &mut stderr,
        },
    );
    Ran {
        code,
        stdout: Vec::new(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
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
    assert_eq!(parse(&args(&["reflect"])), Ok(Invocation::Reflect(27900)));
    assert_eq!(
        parse(&args(&["reflect", "--port", "4000"])),
        Ok(Invocation::Reflect(4000))
    );
    assert_eq!(parse(&args(&["halted-check"])), Ok(Invocation::HaltedCheck));
    assert_eq!(parse(&args(&["target-watch"])), Ok(Invocation::TargetWatch));
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
    assert_eq!(parse(&args(&["watch"])), Ok(Invocation::Watch));
    for bad in ["0", "-1", "+2", "x", ""] {
        assert!(parse(&args(&["txn", bad])).is_err(), "txn {bad:?}");
    }
    for bad in [
        &[][..],
        &["serve-ssh"],
        &["serve-ssh", "--role", "root"],
        &["serve-ssh", "--role", "ops", "extra"],
        &["txn-recover", "1"],
        &["watch", "--once"],
        &["reflect", "--listen", "203.0.113.10"],
        &["reflect", "--port", "70000"],
        &["reflect", "--port"],
        &["halted-check", "now"],
        &["apply"],
    ] {
        assert!(parse(&args(bad)).is_err(), "{bad:?}");
    }
}

/// Arguments that name no command, or are not text, are exit 1 with the
/// usage on stderr; nothing else is done.
#[test]
fn arguments_that_name_no_command_are_answered_with_the_usage() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let usage = "mooring-agent: usage: mooring-agent serve-ssh --role <bootstrap|ops|viewer> | reflect [--port <port>] | halted-check | gate-close | self-test | txn <N> | txn-revert <N> | txn-recover | watch | target-watch\n";
    for arguments in [
        vec![],
        vec![OsString::from("apply")],
        vec![OsString::from_vec(b"self-\xfftest".to_vec())],
        vec![OsString::from("txn"), OsString::from_vec(b"\xff".to_vec())],
    ] {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = entry(
            &arguments,
            &paths,
            &node,
            &mut Process {
                ssh_connection: None,
                stdin: &mut Cursor::new(Vec::new()),
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
        );
        assert_eq!(code, ExitCode::from(1), "{arguments:?}");
        assert_eq!(String::from_utf8(stderr).unwrap(), usage, "{arguments:?}");
        assert!(stdout.is_empty());
    }
    assert!(node.calls().is_empty());
    assert!(!paths.at("/var").exists() && !paths.at("/run").exists());
}

/// `serve-ssh` reads its one request from stdin and answers on stdout;
/// a reply that cannot be written is exit 1 and says so.
#[test]
fn serve_ssh_answers_its_stdin_on_its_stdout() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(10);
    let request = frame(&LineRequest::ClearHold {
        hold: ClearableHold::Operator,
    });
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = entry(
        &[
            OsString::from("serve-ssh"),
            OsString::from("--role"),
            OsString::from("ops"),
        ],
        &paths,
        &node,
        &mut Process {
            ssh_connection: None,
            stdin: &mut Cursor::new(request.clone()),
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        read_reply(&mut Cursor::new(stdout)).unwrap(),
        Ok(Response::HoldCleared { holds: Holds::NONE })
    );
    let refused = refused(Invocation::ServeSsh(Role::Ops), &paths, &node, &request);
    assert_eq!(refused.code, ExitCode::from(1));
    assert!(
        refused
            .stderr
            .starts_with("mooring-agent: writing the reply failed: "),
        "{}",
        refused.stderr
    );
}

#[test]
fn halted_check_exits_1_while_halted() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    assert_eq!(
        ran(Invocation::HaltedCheck, &paths, &node, b"").code,
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
    let halted = ran(Invocation::HaltedCheck, &paths, &node, b"");
    assert_eq!(halted.code, ExitCode::from(1));
    assert!(halted.stderr.is_empty());
}

#[test]
fn gate_close_closes_and_reports_a_failure() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    assert_eq!(
        ran(Invocation::GateClose, &paths, &node, b"").code,
        ExitCode::SUCCESS
    );
    assert_eq!(
        node.calls(),
        vec!["/usr/sbin/nft add element inet mooring exit_closed { \"wgexit\" }".to_owned()]
    );
    let broken = FakeNode::answering(0, Box::new(|_, _| Ok(failed(b"no table"))));
    let refused = ran(Invocation::GateClose, &paths, &broken, b"");
    assert_eq!(refused.code, ExitCode::from(1));
    assert!(
        refused
            .stderr
            .starts_with("mooring-agent: closing the gate failed")
    );
}

/// The self-test prints the protocol on stdout, which `ActivateAgent`
/// compares; damaged state, or a stdout that refuses the line, is exit 1
/// with the reason.
#[test]
fn the_self_test_prints_the_protocol_and_refuses_damaged_state() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let passed = ran(Invocation::SelfTest, &paths, &node, b"");
    assert_eq!(passed.code, ExitCode::SUCCESS);
    assert_eq!(passed.stdout, b"1\n");
    assert!(passed.stderr.is_empty());
    let unprinted = refused(Invocation::SelfTest, &paths, &node, b"");
    assert_eq!(unprinted.code, ExitCode::from(1));
    assert!(
        unprinted
            .stderr
            .starts_with("mooring-agent: printing the protocol failed: "),
        "{}",
        unprinted.stderr
    );
    self_test(&paths).unwrap();
    std::fs::create_dir_all(paths.gate_dir()).unwrap();
    std::fs::write(paths.holds(), "{").unwrap();
    assert!(self_test(&paths).is_err());
    let damaged = ran(Invocation::SelfTest, &paths, &node, b"");
    assert_eq!(damaged.code, ExitCode::from(1));
    assert!(damaged.stdout.is_empty());
    assert!(
        damaged
            .stderr
            .starts_with("mooring-agent: self-test failed: "),
        "{}",
        damaged.stderr
    );
}

/// The reflector reads the uplink's address itself; without one it says so
/// and exits 1, so systemd restarts it until the address is up.
#[test]
fn the_reflector_needs_the_uplinks_address() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let refused = ran(Invocation::Reflect(27900), &paths, &node, b"");
    assert_eq!(refused.code, ExitCode::from(1));
    assert!(
        refused.stderr.contains("the uplink's address is unknown"),
        "{}",
        refused.stderr
    );
    assert!(node.calls().is_empty(), "no route, so no address lookup");
}

/// A reflector that cannot listen on the uplink's address says why and
/// exits 1. The address here is loopback's, on a port the test holds.
#[test]
fn a_reflector_that_cannot_listen_says_why() {
    let (_dir, paths) = scratch();
    let route = paths.at("/proc/net/route");
    std::fs::create_dir_all(route.parent().unwrap()).unwrap();
    std::fs::write(
        &route,
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
         eth0\t00000000\t0100007F\t0003\t0\t0\t0\t00000000\n",
    )
    .unwrap();
    let node = FakeNode::answering(
        0,
        Box::new(|tool, _| {
            Ok(match tool {
                Tool::Ip => ok(
                    br#"[{"addr_info":[{"family":"inet","local":"127.0.0.1","scope":"global"}]}]"#,
                ),
                _ => ok(b""),
            })
        }),
    );
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = held.local_addr().unwrap();
    // What the system says for a second listener on that port.
    let taken = TcpListener::bind(address).unwrap_err();
    let refused = ran(Invocation::Reflect(address.port()), &paths, &node, b"");
    assert_eq!(refused.code, ExitCode::from(1));
    assert_eq!(
        refused.stderr,
        format!("mooring-agent: the reflector cannot listen on {address}: {taken}\n")
    );
}

/// The watch exits 1 with the reading it could not take: systemd restarts
/// it, and `ExecStopPost` closes the gate meanwhile.
#[test]
fn a_watch_that_cannot_read_the_node_exits_1_and_says_what() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let stopped = ran(Invocation::Watch, &paths, &node, b"");
    assert_eq!(stopped.code, ExitCode::from(1));
    assert!(
        stopped
            .stderr
            .starts_with("mooring-agent: a reading the watch needs failed: "),
        "{}",
        stopped.stderr
    );
}

/// The hourly target check exits 0 once it has written its reading, and 1
/// without the generation's configuration to read the target from.
#[test]
fn the_hourly_target_check_exits_0_once_its_reading_is_written() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(5_000);
    let unconfigured = ran(Invocation::TargetWatch, &paths, &node, b"");
    assert_eq!(unconfigured.code, ExitCode::from(1));
    assert!(
        unconfigured
            .stderr
            .starts_with("mooring-agent: the target check failed: "),
        "{}",
        unconfigured.stderr
    );
    let config = paths.watch_config();
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, super::txn::golden(super::txn::WATCH)).unwrap();
    let checked = ran(Invocation::TargetWatch, &paths, &node, b"");
    assert_eq!(checked.code, ExitCode::SUCCESS, "{}", checked.stderr);
    assert!(checked.stderr.is_empty());
    assert!(paths.target_reading().exists());
}
