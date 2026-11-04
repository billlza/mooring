// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::VIEWER_ACCOUNT;

const PROFILE: HostProfile = HostProfile::CURRENT;

const HEADER: &str = "# Managed by Mooring host profile 2. Local changes are overwritten.\n";

#[test]
fn the_current_profile_is_version_2() {
    assert_eq!(PROFILE.version, HostProfileVersion::new(2));
}

/// Only the viewer can log in (sshd runs its forced command through
/// its shell); the watch and the viewer share the state group and no
/// one else is in it; each engine has a group of its own.
#[test]
fn the_accounts_are_the_designed_ones() {
    let accounts: Vec<(&str, &str, &str, &str)> = HostAccount::ALL
        .iter()
        .map(|account| {
            (
                account.name(),
                account.group(),
                account.home(),
                account.shell(),
            )
        })
        .collect();
    assert_eq!(
        accounts,
        [
            (
                "mooring-watch",
                "mooring",
                "/nonexistent",
                "/usr/sbin/nologin"
            ),
            ("mooring-view", "mooring", "/nonexistent", "/bin/sh"),
            (
                "mooring-xray",
                "mooring-xray",
                "/nonexistent",
                "/usr/sbin/nologin"
            ),
            (
                "mooring-hy2",
                "mooring-hy2",
                "/nonexistent",
                "/usr/sbin/nologin"
            ),
        ]
    );
    assert_eq!(HostAccount::Viewer.name(), VIEWER_ACCOUNT);
    for engine in EngineUser::ALL {
        assert!(
            HostAccount::ALL
                .iter()
                .any(|account| account.name() == engine.name() && account.group() == engine.name())
        );
    }
}

/// The layout's security: the blobs (the bundle's secrets) are root's
/// alone; everything else under `/var/lib/mooring` is set-group-ID to
/// the state group, so files root writes there are readable by the
/// watch and the viewer; the stop directory is the only one that group
/// may write, and the viewer owns nothing, so it can never touch the
/// holds; every directory on the way to a program or the viewer's
/// keys is root's and writable by no one else (sshd's StrictModes).
#[test]
fn the_layout_keeps_the_viewer_away_from_the_holds_and_the_secrets() {
    let dirs = PROFILE.directories;
    let dir = |path: &str| *dirs.iter().find(|dir| dir.path == path).unwrap();
    assert_eq!(
        dir("/var/lib/mooring/blobs"),
        StateDir {
            path: "/var/lib/mooring/blobs",
            owner: "root",
            group: "root",
            mode: 0o700,
        }
    );
    let group_writable: Vec<&str> = dirs
        .iter()
        .filter(|dir| dir.mode & 0o022 != 0)
        .map(|dir| dir.path)
        .collect();
    assert_eq!(group_writable, ["/var/lib/mooring/stop"]);
    assert!(dirs.iter().all(|dir| dir.owner != VIEWER_ACCOUNT));
    assert_eq!(dir("/var/lib/mooring/gate").owner, WATCH_ACCOUNT);
    assert_eq!(dir("/var/lib/mooring/gate").mode & 0o070, 0o050);
    for state in dirs
        .iter()
        .filter(|dir| dir.path.starts_with("/var/lib/mooring") && !dir.path.ends_with("blobs"))
    {
        assert_eq!(state.group, STATE_GROUP, "{}", state.path);
        assert_ne!(state.mode & SETGID, 0, "{}", state.path);
        assert_eq!(state.mode & 0o007, 0, "{}", state.path);
    }
    for public in dirs.iter().filter(|dir| !dir.path.starts_with("/var/lib")) {
        assert_eq!(
            (public.owner, public.group, public.mode),
            ("root", "root", 0o755),
            "{}",
            public.path
        );
    }
    // Each directory comes after its parent.
    for (index, child) in dirs.iter().enumerate() {
        let parent = child.path.rsplit_once('/').unwrap().0;
        if let Some(position) = dirs.iter().position(|dir| dir.path == parent) {
            assert!(position < index, "{}", child.path);
        }
    }
    assert!(dir(ETC_DIR).mode == 0o755);
    assert!(
        dir("/usr/local/lib/mooring/agent").path == AGENT_CURRENT_PATH.rsplit_once('/').unwrap().0
    );
    assert!(XRAY_ASSET_DIR.starts_with(dir("/opt/mooring/engines/geodata").path));
}

#[test]
fn the_watch_writes_only_its_own_directories_and_the_lock() {
    assert_eq!(
        PROFILE.watch_writable(),
        [
            "/var/lib/mooring/gate",
            "/var/lib/mooring/stop",
            "/var/lib/mooring/watch",
            "/var/lib/mooring/usage",
            "/run/mooring",
        ]
    );
}

#[test]
fn the_engine_units_have_their_fixed_text() {
    let tail = "LimitNOFILE=65535\n\
                    NoNewPrivileges=yes\n\
                    ProtectSystem=strict\n\
                    ProtectHome=yes\n\
                    PrivateTmp=yes\n\
                    PrivateDevices=yes\n\
                    ProtectKernelTunables=yes\n\
                    ProtectKernelModules=yes\n\
                    ProtectControlGroups=yes\n\
                    RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n\
                    RestrictNamespaces=yes\n\
                    LockPersonality=yes\n\
                    SystemCallArchitectures=native\n\
                    \n\
                    [Install]\n\
                    WantedBy=multi-user.target\n";
    assert_eq!(
        PROFILE.render(HostFile::XrayUnit),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring Xray: REALITY and the Hysteria2 handoff\n\
                 After=wg-quick@wgexit.service nftables.service\n\
                 BindsTo=wg-quick@wgexit.service\n\
                 ConditionPathExists=/etc/mooring/current/xray.json\n\
                 StartLimitIntervalSec=600\n\
                 StartLimitBurst=5\n\
                 \n\
                 [Service]\n\
                 User=mooring-xray\n\
                 Group=mooring-xray\n\
                 ExecCondition=+/usr/local/lib/mooring/agent/current halted-check\n\
                 ExecStart=/etc/mooring/current/engines/xray run -c /etc/mooring/current/xray.json\n\
                 Environment=XRAY_LOCATION_ASSET=/opt/mooring/engines/geodata/current\n\
                 Environment=GOMEMLIMIT=480MiB\n\
                 AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
                 CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
                 Restart=on-failure\n\
                 MemoryMax=600M\n\
                 TasksMax=1024\n\
                 {tail}"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::Hy2Unit),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring Hysteria2\n\
                 After=mooring-xray.service nftables.service\n\
                 ConditionPathExists=/etc/mooring/current/hy2.json\n\
                 StartLimitIntervalSec=600\n\
                 StartLimitBurst=5\n\
                 \n\
                 [Service]\n\
                 User=mooring-hy2\n\
                 Group=mooring-hy2\n\
                 ExecCondition=+/usr/local/lib/mooring/agent/current halted-check\n\
                 ExecStart=/etc/mooring/current/engines/mooring-hy2 run -c /etc/mooring/current/hy2.json\n\
                 Environment=GOMEMLIMIT=160MiB\n\
                 CapabilityBoundingSet=\n\
                 Restart=on-failure\n\
                 MemoryMax=200M\n\
                 TasksMax=512\n\
                 {tail}"
        )
    );
}

#[test]
fn the_watch_reflector_and_recovery_units_have_their_fixed_text() {
    let sandbox = "LimitNOFILE=65535\n\
                       NoNewPrivileges=yes\n\
                       ProtectSystem=strict\n\
                       ProtectHome=yes\n\
                       PrivateTmp=yes\n\
                       PrivateDevices=yes\n\
                       ProtectKernelTunables=yes\n\
                       ProtectKernelModules=yes\n\
                       ProtectControlGroups=yes\n\
                       RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n\
                       RestrictNamespaces=yes\n\
                       LockPersonality=yes\n\
                       SystemCallArchitectures=native\n";
    let install = "\n[Install]\nWantedBy=multi-user.target\n";
    assert_eq!(
        PROFILE.render(HostFile::WatchUnit),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring watch: the gate, accounting and the node's status\n\
                 After=nftables.service wg-quick@wgexit.service\n\
                 StartLimitIntervalSec=0\n\
                 \n\
                 [Service]\n\
                 User=mooring-watch\n\
                 Group=mooring\n\
                 ExecStart=/usr/local/lib/mooring/agent/current watch\n\
                 ExecStopPost=+/usr/local/lib/mooring/agent/current gate-close\n\
                 Restart=always\n\
                 RestartSec=2\n\
                 AmbientCapabilities=CAP_NET_ADMIN\n\
                 CapabilityBoundingSet=CAP_NET_ADMIN\n\
                 ReadWritePaths=/var/lib/mooring/gate /var/lib/mooring/stop /var/lib/mooring/watch /var/lib/mooring/usage /run/mooring\n\
                 {sandbox}{install}"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::ReflectUnit),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring reflector\n\
                 Wants=network-online.target\n\
                 After=network-online.target nftables.service\n\
                 \n\
                 [Service]\n\
                 DynamicUser=yes\n\
                 ExecStart=/usr/local/lib/mooring/agent/current reflect\n\
                 Restart=always\n\
                 RestartSec=5\n\
                 CapabilityBoundingSet=\n\
                 {sandbox}{install}"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::RecoverUnit),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring: revert a change a reboot left unconfirmed\n\
                 After=nftables.service wg-quick@wgexit.service mooring-xray.service mooring-hy2.service\n\
                 \n\
                 [Service]\n\
                 Type=oneshot\n\
                 ExecStart=/usr/local/lib/mooring/agent/current txn-recover\n\
                 {install}"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::TunnelDropIn),
        format!("{HEADER}[Unit]\nConditionPathExists=/etc/wireguard/wgexit.conf\n")
    );
    assert_eq!(
        PROFILE.render(HostFile::TargetCheckUnit),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring: the hourly REALITY target check\n\
                 ConditionPathExists=/etc/mooring/current/watch.json\n\
                 \n\
                 [Service]\n\
                 Type=oneshot\n\
                 User=mooring-watch\n\
                 Group=mooring\n\
                 ExecStart=/usr/local/lib/mooring/agent/current target-watch\n\
                 ReadWritePaths=/var/lib/mooring/watch\n\
                 CapabilityBoundingSet=\n\
                 {sandbox}"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::TargetCheckTimer),
        format!(
            "{HEADER}[Unit]\n\
                 Description=Mooring: run the REALITY target check every hour\n\
                 \n\
                 [Timer]\n\
                 OnBootSec=5min\n\
                 OnUnitActiveSec=1h\n\
                 \n\
                 [Install]\n\
                 WantedBy=timers.target\n"
        )
    );
}

/// Every unit file defines the unit it is named after, every profile
/// unit is enabled, and the tunnel's names agree with the interface.
#[test]
fn the_units_are_named_by_their_files_and_enabled() {
    let units: Vec<&str> = HostFile::ALL
        .iter()
        .filter_map(|file| file.unit())
        .collect();
    // A unit is enabled exactly when it can be: it has an `[Install]`
    // section. The target check's service is started by its timer.
    for file in HostFile::ALL {
        if let Some(unit) = file.unit() {
            assert_eq!(file.path(), format!("/etc/systemd/system/{unit}"));
            assert_eq!(file.staged_name(), unit);
            assert_eq!(
                ENABLED_UNITS.contains(&unit),
                PROFILE.render(*file).contains("\n[Install]\n"),
                "{unit}"
            );
        }
    }
    assert_eq!(units.len(), 7);
    assert!(!ENABLED_UNITS.contains(&"mooring-target-check.service"));
    assert_eq!(
        TUNNEL_UNIT,
        format!("wg-quick@{}.service", crate::WG_INTERFACE)
    );
    assert_eq!(
        HostFile::TunnelDropIn.path(),
        format!("/etc/systemd/system/{TUNNEL_UNIT}.d/10-mooring.conf")
    );
    assert!(ENABLED_UNITS.contains(&TUNNEL_UNIT));
    for engine in EngineUser::ALL {
        assert!(units.contains(&format!("{}.service", engine.name()).as_str()));
    }
}

#[test]
fn sysctl_file_carries_the_section_8_6_values() {
    assert_eq!(
        PROFILE.render(HostFile::Sysctl),
        "# Managed by Mooring host profile 2. Local changes are overwritten.\n\
             net.core.default_qdisc = fq\n\
             net.ipv4.tcp_congestion_control = bbr\n\
             net.ipv4.tcp_slow_start_after_idle = 0\n\
             net.ipv4.tcp_notsent_lowat = 131072\n\
             net.core.rmem_max = 7500000\n\
             net.core.wmem_max = 7500000\n\
             net.ipv4.conf.all.rp_filter = 2\n\
             net.ipv4.conf.default.rp_filter = 2\n\
             net.ipv4.ip_forward = 0\n"
    );
    assert_eq!(
        PROFILE.sysctls[1].proc_path(),
        "/proc/sys/net/ipv4/tcp_congestion_control"
    );
    assert_eq!(
        PROFILE.sysctls[6].proc_path(),
        "/proc/sys/net/ipv4/conf/all/rp_filter"
    );
}

/// The exact drop-in: every directive once, then the viewer's `Match`
/// block (tab-indented) with its root-owned keys file and forced
/// command.
#[test]
fn sshd_drop_in_sets_every_directive_once() {
    assert_eq!(
        PROFILE.render(HostFile::SshdDropIn),
        "# Managed by Mooring host profile 2. Local changes are overwritten.\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PermitRootLogin forced-commands-only\n\
             AuthenticationMethods publickey\n\
             AllowTcpForwarding no\n\
             AllowAgentForwarding no\n\
             AllowStreamLocalForwarding no\n\
             PermitTunnel no\n\
             X11Forwarding no\n\
             MaxAuthTries 3\n\
             AllowUsers root mooring-view\n\
             Match User mooring-view\n\
             \tAuthorizedKeysFile /etc/mooring/current/viewer_authorized_keys\n\
             \tForceCommand /usr/local/lib/mooring/agent/current serve-ssh --role viewer\n"
    );
    assert!(HostFile::SshdDropIn.path() < "/etc/ssh/sshd_config.d/50-cloud-init.conf");
}

/// `sshd -T` prints one `allowusers` line per user and one line for
/// every other directive.
#[test]
fn sshd_effective_lines_list_each_allowed_user() {
    assert_eq!(
        PROFILE.sshd_effective_lines(SshdDirective::AllowUsers),
        ["allowusers root", "allowusers mooring-view"]
    );
    assert_eq!(
        PROFILE.sshd_effective_lines(SshdDirective::PermitRootLogin),
        ["permitrootlogin forced-commands-only"]
    );
    for directive in SshdDirective::ALL {
        let lines = PROFILE.sshd_effective_lines(*directive);
        let keyword = directive.keyword().to_ascii_lowercase();
        let values: Vec<&str> = lines
            .iter()
            .map(|line| line.strip_prefix(&format!("{keyword} ")).unwrap())
            .collect();
        assert_eq!(
            values.join(" "),
            PROFILE.sshd_value(*directive),
            "{directive:?}"
        );
        assert_eq!(
            lines.len(),
            if *directive == SshdDirective::AllowUsers {
                2
            } else {
                1
            },
            "{directive:?}"
        );
    }
}

#[test]
fn the_other_files_have_their_fixed_text() {
    let header = HEADER;
    assert_eq!(
        PROFILE.render(HostFile::KernelModules),
        format!("{header}tcp_bbr\n")
    );
    assert_eq!(
        PROFILE.render(HostFile::Journald),
        format!(
            "{header}[Journal]\nStorage=persistent\nSystemMaxUse=200M\nMaxRetentionSec=14day\n"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::Tmpfiles),
        format!(
            "{header}d /run/mooring 0750 root mooring -\n\
                 f /run/mooring/gate.lock 0660 root mooring -\n\
                 a+ /var/log/unattended-upgrades - - - - u:mooring-watch:x\n"
        )
    );
    assert_eq!(
        PROFILE.render(HostFile::UnattendedUpgrades),
        format!(
            "{header}APT::Periodic::Update-Package-Lists \"1\";\n\
                 APT::Periodic::Unattended-Upgrade \"1\";\n\
                 #clear Unattended-Upgrade::Origins-Pattern;\n\
                 Unattended-Upgrade::Origins-Pattern {{\n\
                 \t\"origin=Debian,codename=${{distro_codename}}-security,label=Debian-Security\";\n\
                 }};\n\
                 Unattended-Upgrade::Automatic-Reboot \"true\";\n\
                 Unattended-Upgrade::Automatic-Reboot-Time \"20:00\";\n"
        )
    );
}

#[test]
fn host_files_have_distinct_absolute_paths() {
    let files = PROFILE.files();
    assert_eq!(files.len(), HostFile::ALL.len());
    let mut paths: Vec<_> = HostFile::ALL.iter().map(|file| file.path()).collect();
    paths.sort_unstable();
    paths.dedup();
    assert_eq!(paths.len(), HostFile::ALL.len());
    assert!(paths.iter().all(|path| path.starts_with("/etc/")));
    let mut staged: Vec<_> = HostFile::ALL
        .iter()
        .map(|file| file.staged_name())
        .collect();
    staged.sort_unstable();
    staged.dedup();
    assert_eq!(staged.len(), HostFile::ALL.len());
    assert!(staged.iter().all(|name| !name.contains('/')));
}
