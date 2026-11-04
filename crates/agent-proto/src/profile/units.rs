// SPDX-License-Identifier: GPL-3.0-or-later

//! Systemd service and timer rendering, with their shared hardening.

use crate::{AGENT_CURRENT_PATH, CURRENT_DIR, EngineUser, ManagedFile, STATE_GROUP, WATCH_ACCOUNT};

use super::XRAY_ASSET_DIR;

/// The tunnel's unit, Debian's `wg-quick@.service` for [`crate::WG_INTERFACE`].
pub(crate) const TUNNEL_UNIT: &str = "wg-quick@wgexit.service";

/// The sandbox of the engine, watch and reflector units (design §5.2).
pub(super) fn hardening() -> Vec<String> {
    [
        "LimitNOFILE=65535",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
        "RestrictNamespaces=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// A unit's `[Install]` section, after a blank line.
pub(super) fn install() -> Vec<String> {
    vec![
        String::new(),
        "[Install]".to_owned(),
        "WantedBy=multi-user.target".to_owned(),
    ]
}

/// An engine's unit (design §5.2): its own user, Xray with
/// `CAP_NET_BIND_SERVICE` only and Hysteria2 with none, started only once
/// a generation is installed and never while the node is halted
/// (`ExecCondition`, run as root, which can read the marker), restarted on
/// failure at most five times in ten minutes, and bounded in memory.
pub(super) fn engine_unit(engine: EngineUser) -> Vec<String> {
    let (description, after, config, capability, memory, tasks, go_limit) = match engine {
        EngineUser::Xray => (
            "Mooring Xray: REALITY and the Hysteria2 handoff",
            format!("{TUNNEL_UNIT} nftables.service"),
            ManagedFile::XrayConfig,
            "CAP_NET_BIND_SERVICE",
            "600M",
            "1024",
            "480MiB",
        ),
        EngineUser::Hy2 => (
            "Mooring Hysteria2",
            "mooring-xray.service nftables.service".to_owned(),
            ManagedFile::Hy2Config,
            "",
            "200M",
            "512",
            "160MiB",
        ),
    };
    let mut lines = vec![
        "[Unit]".to_owned(),
        format!("Description={description}"),
        format!("After={after}"),
    ];
    if engine == EngineUser::Xray {
        // Xray's exit outbound binds to the tunnel: it goes when the
        // tunnel goes.
        lines.push(format!("BindsTo={TUNNEL_UNIT}"));
    }
    lines.extend([
        format!("ConditionPathExists={}", config.current_path()),
        "StartLimitIntervalSec=600".to_owned(),
        "StartLimitBurst=5".to_owned(),
        String::new(),
        "[Service]".to_owned(),
        format!("User={}", engine.name()),
        format!("Group={}", engine.name()),
        format!("ExecCondition=+{AGENT_CURRENT_PATH} halted-check"),
        format!(
            "ExecStart={CURRENT_DIR}/engines/{} run -c {}",
            engine.program(),
            config.current_path()
        ),
    ]);
    if engine == EngineUser::Xray {
        lines.push(format!("Environment=XRAY_LOCATION_ASSET={XRAY_ASSET_DIR}"));
    }
    lines.push(format!("Environment=GOMEMLIMIT={go_limit}"));
    if !capability.is_empty() {
        lines.push(format!("AmbientCapabilities={capability}"));
    }
    lines.extend([
        format!("CapabilityBoundingSet={capability}"),
        "Restart=on-failure".to_owned(),
        format!("MemoryMax={memory}"),
        format!("TasksMax={tasks}"),
    ]);
    lines.extend(hardening());
    lines.extend(install());
    lines
}

/// `mooring-reflect.service` (design §11.4): a dynamic user with no
/// capability, on the uplink's address, which the agent reads itself.
pub(super) fn reflect_unit() -> Vec<String> {
    let mut lines = vec![
        "[Unit]".to_owned(),
        "Description=Mooring reflector".to_owned(),
        "Wants=network-online.target".to_owned(),
        "After=network-online.target nftables.service".to_owned(),
        String::new(),
        "[Service]".to_owned(),
        "DynamicUser=yes".to_owned(),
        format!("ExecStart={AGENT_CURRENT_PATH} reflect"),
        "Restart=always".to_owned(),
        "RestartSec=5".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
    ];
    lines.extend(hardening());
    lines.extend(install());
    lines
}

/// `mooring-target-check.service` (design §11.3): the hourly check of the
/// configured target, as the watch's account with no capability, writing
/// only the watch's directory; it runs once a generation is installed.
/// The timer starts it, so it has no `[Install]`.
pub(super) fn target_check_unit() -> Vec<String> {
    let mut lines = vec![
        "[Unit]".to_owned(),
        "Description=Mooring: the hourly REALITY target check".to_owned(),
        format!(
            "ConditionPathExists={}",
            ManagedFile::WatchConfig.current_path()
        ),
        String::new(),
        "[Service]".to_owned(),
        "Type=oneshot".to_owned(),
        format!("User={WATCH_ACCOUNT}"),
        format!("Group={STATE_GROUP}"),
        format!("ExecStart={AGENT_CURRENT_PATH} target-watch"),
        "ReadWritePaths=/var/lib/mooring/watch".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
    ];
    lines.extend(hardening());
    lines
}

/// `mooring-target-check.timer`: five minutes after boot, then an hour
/// after each run.
pub(super) fn target_check_timer() -> Vec<String> {
    vec![
        "[Unit]".to_owned(),
        "Description=Mooring: run the REALITY target check every hour".to_owned(),
        String::new(),
        "[Timer]".to_owned(),
        "OnBootSec=5min".to_owned(),
        "OnUnitActiveSec=1h".to_owned(),
        String::new(),
        "[Install]".to_owned(),
        "WantedBy=timers.target".to_owned(),
    ]
}

/// `mooring-txn-recover.service` (design §11.2): at boot, after the
/// ruleset, the tunnel and both engines, revert whatever change a reboot
/// left pending (its confirm timer was lost with the reboot).
pub(super) fn recover_unit() -> Vec<String> {
    let mut lines = vec![
        "[Unit]".to_owned(),
        "Description=Mooring: revert a change a reboot left unconfirmed".to_owned(),
        format!("After=nftables.service {TUNNEL_UNIT} mooring-xray.service mooring-hy2.service"),
        String::new(),
        "[Service]".to_owned(),
        "Type=oneshot".to_owned(),
        format!("ExecStart={AGENT_CURRENT_PATH} txn-recover"),
    ];
    lines.extend(install());
    lines
}
