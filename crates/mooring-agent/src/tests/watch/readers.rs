// SPDX-License-Identifier: GPL-3.0-or-later

//! What the watch reads, each reader on its own (design §11.3, §11.5): the
//! Mac peer, the host's figures, the engine units, the nft counters and the
//! uplink's counters, parsed exactly, and what each refuses; the host's
//! conditions (disk low under 1 GiB free or under a tenth); and the
//! uplink's transfer, where another interface or a counter below the last
//! reading is a reset. A refused host, engine, nft or uplink reading is an
//! error the watch ends on; a refused Mac peer closes the gate instead
//! (`WgReadFailed`), and chrony's answer without a leap status is read as
//! not synchronised. A journal entry removed since its listing occupies
//! nothing; any other that cannot be read is the host reading's error.

use std::fs;
use std::io;
use std::time::{Duration, UNIX_EPOCH};

use mooring_agent_proto::{
    AgentError, EngineRun, EngineState, EngineUser, IfName, IoOp, UnixTime, UsageMonth, WatchError,
};

use super::world::{BOOT, OCT_8, World};
use crate::host::{Tool, ToolOutput};
use crate::store::malformed;
use crate::tests::{ENOENT, ENOTDIR, FakeNode, failed, ok};
use crate::watch::engines;
use crate::watch::host;
use crate::watch::status::HostReading;
use crate::watch::transfer::{self, Counters, Transfer};

#[test]
fn the_readings_are_parsed_exactly() {
    use crate::watch::host::{load_milli, mem_available, synchronised, uptime};
    use crate::wg::parse_dump;
    let dump = "PRIVATE=\tPUBLIC=\t27820\toff\nMAC=\t(none)\t198.51.100.7:4500\t10.66.0.2/32\t1790000000\t123\t456\t10\n";
    let peer = parse_dump(dump.as_bytes()).unwrap();
    assert_eq!(
        peer.latest_handshake,
        Some(UnixTime::from_secs(1_790_000_000))
    );
    assert_eq!(peer.rx_bytes, 123, "rx is the sixth field, not tx");
    let none = dump.replace("1790000000", "0");
    assert_eq!(parse_dump(none.as_bytes()).unwrap().latest_handshake, None);
    let refused = malformed(IoOp::ReadState);
    for bad in [
        Vec::new(),
        b"PRIVATE=\tPUBLIC=\t27820\toff\n".to_vec(),
        dump.replace("\t123\t", "\t-1\t").into_bytes(),
        dump.replace("\t10\n", "\n").into_bytes(),
        format!("{dump}{}", dump.lines().nth(1).unwrap()).into_bytes(),
        // Not text.
        [b"\xff".as_slice(), dump.as_bytes()].concat(),
    ] {
        assert_eq!(parse_dump(&bad).unwrap_err(), refused, "{bad:?}");
    }

    assert_eq!(uptime("350735.47 234388.90\n").unwrap(), 350_735);
    assert_eq!(uptime("12 3\n").unwrap(), 12);
    assert_eq!(uptime("").unwrap_err(), refused);
    assert_eq!(uptime("soon 1\n").unwrap_err(), refused);

    assert_eq!(load_milli("0.52 0.58 0.59 1/123 4567\n").unwrap(), 520);
    assert_eq!(load_milli("12.05 1 1\n").unwrap(), 12_050);
    assert_eq!(load_milli("3 1 1\n").unwrap(), 3_000);
    assert_eq!(load_milli("0.125 1 1\n").unwrap(), 125);
    assert_eq!(load_milli("007.5 1 1\n").unwrap(), 7_500);
    assert_eq!(
        load_milli("4294967.295 1 1\n").unwrap(),
        u32::MAX,
        "the most thousandths there are"
    );
    for bad in [
        "",
        "-1.00 1 1",
        "1.2345 1 1",
        "1. 1 1",
        ".5 1 1",
        "x.50 1 1",
        "4294967.296 1 1",
        "4294968 1 1",
    ] {
        assert_eq!(load_milli(bad).unwrap_err(), refused, "{bad:?}");
    }

    assert_eq!(
        mem_available("MemTotal: 9 kB\nMemFree: 1 kB\nMemAvailable:   1500 kB\n").unwrap(),
        1500 * 1024
    );
    for bad in [
        "MemTotal: 9 kB\n",
        "MemAvailable: 15 MB\n",
        "MemAvailable: lots kB\n",
    ] {
        assert_eq!(mem_available(bad).unwrap_err(), refused, "{bad:?}");
    }

    for (status, synced) in [
        ("Normal", true),
        ("Insert second", true),
        ("Delete second", true),
        ("Not synchronised", false),
    ] {
        assert_eq!(
            synchronised(&format!("Reference ID : 0\nLeap status     : {status}\n")),
            synced,
            "{status}"
        );
    }
    assert!(!synchronised("Reference ID : 0\n"), "no leap status");
}

#[test]
fn disk_low_is_under_1_gib_or_under_a_tenth_free() {
    use crate::watch::host::conditions;
    let reading = |free: u64, total: u64| HostReading {
        at: UnixTime::from_secs(1),
        health: mooring_agent_proto::HostHealth {
            uptime_secs: 1,
            load_milli: 0,
            mem_available_bytes: 1,
            disk_free_bytes: free,
            journal_bytes: 0,
            reboot_required: false,
            last_unattended_upgrade: None,
            ntp_synced: true,
        },
        disk_total_bytes: total,
        reboot_required_since: None,
    };
    let gib = 1 << 30;
    assert!(
        conditions(&reading(gib, 2 * gib)).is_empty(),
        "exactly 1 GiB"
    );
    assert_eq!(
        conditions(&reading(gib - 1, 2 * gib)),
        vec![WatchError::DiskLow { free: gib - 1 }]
    );
    assert!(
        conditions(&reading(10 * gib, 100 * gib)).is_empty(),
        "exactly 10 %"
    );
    assert_eq!(
        conditions(&reading(10 * gib - 1, 100 * gib)),
        vec![WatchError::DiskLow { free: 10 * gib - 1 }]
    );
}

#[test]
fn systemctl_show_and_nft_counters_are_parsed_exactly() {
    use crate::watch::engines::{Unit, parse_show};
    use crate::watch::nft::counter_packets;
    // As systemd 257 printed it on the London VPS, in its own order.
    let active = b"NRestarts=3\nActiveState=active\nActiveEnterTimestampMonotonic=15699978\n";
    let unit = parse_show(active).unwrap();
    assert_eq!(
        unit,
        Unit {
            active_since: Some(15),
            restarts: 3
        }
    );
    assert_eq!(
        unit.state(100, Some(7)),
        EngineState {
            restarts: 3,
            run: EngineRun::Active {
                uptime_secs: 85,
                go_heap_bytes: Some(7)
            }
        }
    );
    assert_eq!(
        Unit {
            active_since: Some(101),
            restarts: 0
        }
        .state(100, None)
        .run,
        EngineRun::Active {
            uptime_secs: 0,
            go_heap_bytes: None
        },
        "rounding can put the activation a second ahead"
    );
    let never = b"NRestarts=0\nActiveState=inactive\nActiveEnterTimestampMonotonic=0\n";
    assert_eq!(
        parse_show(never).unwrap().state(100, None),
        EngineState {
            restarts: 0,
            run: EngineRun::Inactive
        }
    );
    for state in ["failed", "activating", "deactivating", "maintenance"] {
        let text = format!("NRestarts=0\nActiveState={state}\nActiveEnterTimestampMonotonic=5\n");
        assert_eq!(
            parse_show(text.as_bytes()).unwrap().active_since,
            None,
            "{state}"
        );
    }
    for state in ["reloading", "refreshing"] {
        let text =
            format!("NRestarts=0\nActiveState={state}\nActiveEnterTimestampMonotonic=5000000\n");
        assert_eq!(
            parse_show(text.as_bytes()).unwrap().active_since,
            Some(5),
            "{state}"
        );
    }
    let refused = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    for bad in [
        "NRestarts=0\nActiveState=active\n",
        "NRestarts=0\nNRestarts=0\nActiveState=active\nActiveEnterTimestampMonotonic=1\n",
        "NRestarts=0\nActiveState=active\nActiveEnterTimestampMonotonic=1\nSubState=running\n",
        "NRestarts=0\nActiveState=sleeping\nActiveEnterTimestampMonotonic=1\n",
        "NRestarts=4294967296\nActiveState=active\nActiveEnterTimestampMonotonic=1\n",
        "NRestarts=-1\nActiveState=active\nActiveEnterTimestampMonotonic=1\n",
        "NRestarts=0\nActiveState=active\nActiveEnterTimestampMonotonic=@1\n",
        "NRestarts 0\nActiveState=active\nActiveEnterTimestampMonotonic=1\n",
    ] {
        assert_eq!(parse_show(bad.as_bytes()), Err(refused.clone()), "{bad:?}");
    }
    let listing = br#"{"nftables":[{"metainfo":{"version":"1.1.3"}},{"counter":{"family":"inet","name":"probe_flows","table":"mooring","handle":5,"packets":12,"bytes":720}}]}"#;
    assert_eq!(counter_packets(listing), Ok(12));
    for bad in [
        r#"{"nftables":[{"metainfo":{"version":"1.1.3"}}]}"#,
        r#"{"nftables":[{"counter":{"packets":1}},{"counter":{"packets":2}}]}"#,
        r#"{"nftables":[{"counter":{"packets":-1}}]}"#,
        "Error",
    ] {
        assert_eq!(
            counter_packets(bad.as_bytes()),
            Err(refused.clone()),
            "{bad}"
        );
    }
}

#[test]
fn another_uplink_interface_is_a_counter_reset() {
    let reading = |interface: &str, rx: u64| Counters {
        boot_id: BOOT.to_owned(),
        interface: IfName::new(interface).unwrap(),
        rx_bytes: rx,
        tx_bytes: rx,
    };
    let now = UnixTime::from_secs(OCT_8);
    let first = Transfer::next(None, now, reading("eth0", 1_000)).unwrap();
    let grown = Transfer::next(Some(&first), now, reading("eth0", 1_200)).unwrap();
    assert_eq!(
        (grown.reported.rx_bytes, grown.reported.counter_resets),
        (200, 0)
    );
    let moved = Transfer::next(Some(&grown), now, reading("ens3", 5_000)).unwrap();
    assert_eq!(
        (moved.reported.rx_bytes, moved.reported.counter_resets),
        (5_200, 1)
    );
    // Only tx below the last reading.
    let tx_reset = Counters {
        tx_bytes: 10,
        ..reading("ens3", 6_000)
    };
    let after = Transfer::next(Some(&moved), now, tx_reset).unwrap();
    assert_eq!(
        (
            after.reported.rx_bytes,
            after.reported.tx_bytes,
            after.reported.counter_resets
        ),
        (5_200 + 6_000, 5_200 + 10, 2)
    );
}

/// The host read on a node whose `stat -f` answers `stat`.
fn host_with_stat(stat: ToolOutput) -> Result<HostReading, AgentError> {
    let world = World::new();
    let node = world.node_answering(1, move |tool, _| {
        (tool == Tool::Stat).then(|| Ok(stat.clone()))
    });
    host::read(&world.paths, &node, UnixTime::from_secs(1))
}

#[test]
fn a_filesystem_stat_does_not_size_is_no_host_reading() {
    let reading = host_with_stat(ok(b"2000000 4096 2500000\n")).unwrap();
    assert_eq!(
        (reading.health.disk_free_bytes, reading.disk_total_bytes),
        (2_000_000 * 4096, 2_500_000 * 4096)
    );
    for stat in [
        failed(b"stat: cannot read file system information: No such file or directory\n"),
        ok(b"\xff 4096 2500000\n"),
        ok(b"2000000 4096 lots\n"),
        ok(b"2000000 4096\n"),
        ok(b"2000000 4096 2500000 1\n"),
        ok(b"18446744073709551615 4096 1\n"),
    ] {
        assert_eq!(
            host_with_stat(stat.clone()),
            Err(malformed(IoOp::ReadState)),
            "{stat:?}"
        );
    }
}

#[test]
fn host_files_that_cannot_be_read_are_no_host_reading() {
    let reading = |world: &World| host::read(&world.paths, &world.node(1), UnixTime::from_secs(1));
    let world = World::new();
    world.write("/var/log/journal", "not a directory");
    assert_eq!(
        reading(&world),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOTDIR)
        }),
        "the persistent journal"
    );
    let world = World::new();
    world.write("/var/log/unattended-upgrades", "not a directory");
    assert_eq!(
        reading(&world),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOTDIR)
        }),
        "the upgrade log"
    );
    // A mark dated before 1970 has no time the watch can report.
    let world = World::new();
    world.write("/run/reboot-required", "*** System restart required ***\n");
    fs::File::options()
        .write(true)
        .open(world.paths.reboot_required())
        .unwrap()
        .set_modified(UNIX_EPOCH - Duration::from_secs(86_400))
        .unwrap();
    assert_eq!(reading(&world), Err(malformed(IoOp::ReadState)));
}

#[test]
fn an_engine_unit_systemd_cannot_show_is_no_reading() {
    let unstartable = FakeNode::answering(
        1,
        Box::new(|_, _| Err(io::Error::from_raw_os_error(ENOENT))),
    );
    assert_eq!(
        engines::read(&unstartable, EngineUser::Xray),
        Err(AgentError::Io {
            op: IoOp::SpawnProcess,
            errno: Some(ENOENT)
        })
    );
    let failing = FakeNode::answering(
        1,
        Box::new(|_, _| {
            Ok(failed(
                b"Failed to connect to bus: No such file or directory\n",
            ))
        }),
    );
    assert_eq!(
        engines::read(&failing, EngineUser::Hy2),
        Err(malformed(IoOp::ReadState))
    );
    assert_eq!(
        failing.calls(),
        [
            "/usr/bin/systemctl show -p ActiveState,NRestarts,ActiveEnterTimestampMonotonic mooring-hy2.service"
        ]
    );
    assert_eq!(
        engines::parse_show(b"NRestarts=0\nActiveState=\xff\nActiveEnterTimestampMonotonic=1\n"),
        Err(malformed(IoOp::ReadState)),
        "not text"
    );
}

#[test]
fn uplink_counters_that_cannot_be_read_are_no_reading() {
    let world = World::new();
    assert_eq!(
        transfer::read(&world.paths, BOOT),
        Ok(Counters {
            boot_id: BOOT.to_owned(),
            interface: IfName::new("eth0").unwrap(),
            rx_bytes: 1_000,
            tx_bytes: 2_000,
        })
    );
    fs::remove_file(world.paths.at("/sys/class/net/eth0/statistics/tx_bytes")).unwrap();
    assert_eq!(
        transfer::read(&world.paths, BOOT),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOENT)
        })
    );
    world.uplink(1_000, 2_000);
    world.write("/sys/class/net/eth0/statistics/rx_bytes", "lots\n");
    assert_eq!(
        transfer::read(&world.paths, BOOT),
        Err(malformed(IoOp::ReadState))
    );
}

#[test]
fn a_transfer_past_the_last_month_is_refused() {
    let counters = Counters {
        boot_id: BOOT.to_owned(),
        interface: IfName::new("eth0").unwrap(),
        rx_bytes: 1,
        tx_bytes: 1,
    };
    // 9999-12-31T23:59:59Z, the last second a month holds, then the next.
    let last =
        Transfer::next(None, UnixTime::from_secs(253_402_300_799), counters.clone()).unwrap();
    assert_eq!(last.reported.month, UsageMonth::new(9999, 12).unwrap());
    assert_eq!(
        Transfer::next(Some(&last), UnixTime::from_secs(253_402_300_800), counters),
        Err(malformed(IoOp::ReadState))
    );
}

/// An entry the journal's listing named but journald has removed since is
/// no failed reading: it occupies nothing. Anything else unreadable is the
/// reading's error.
#[test]
fn an_entry_gone_since_it_was_listed_occupies_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(host::entry_bytes(&dir.path().join("vacuumed")), Ok(0));
    let file = dir.path().join("system.journal");
    fs::write(&file, b"twelve bytes").unwrap();
    assert_eq!(host::entry_bytes(&file), Ok(12));
    assert_eq!(host::entry_bytes(dir.path()), Ok(12));
    std::os::unix::fs::symlink("system.journal", dir.path().join("link")).unwrap();
    assert_eq!(host::entry_bytes(&dir.path().join("link")), Ok(0));
    assert_eq!(
        host::entry_bytes(&file.join("below")),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOTDIR),
        })
    );
}
