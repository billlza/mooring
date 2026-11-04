// SPDX-License-Identifier: GPL-3.0-or-later

//! The host profile (design §8.6): constant host configuration, versioned,
//! compiled into the agent and converged in every transaction. The data and
//! the exact file text live here, once, for the agent and the renderer.

mod types;
mod units;

#[cfg(test)]
mod tests;

pub use types::{
    ENABLED_UNITS, HostAccount, HostFile, HostProfileVersion, JournaldSetting, PACKAGES, SETGID,
    SearchGrant, SshdDirective, StateDir, Sysctl, TmpfilesEntry, TmpfilesType, UnattendedUpgrades,
    XRAY_ASSET_DIR,
};
pub(crate) use units::TUNNEL_UNIT;
use units::{
    engine_unit, hardening, install, recover_unit, reflect_unit, target_check_timer,
    target_check_unit,
};

use crate::vps::viewer_account;
use crate::{
    AGENT_CURRENT_PATH, ETC_DIR, EngineUser, ManagedFile, Role, STATE_GROUP, WATCH_ACCOUNT,
};

/// The constant host configuration of one profile version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProfile {
    /// The version.
    pub version: HostProfileVersion,
    /// `/etc/sysctl.d/60-mooring.conf`, in file order.
    pub sysctls: &'static [Sysctl],
    /// Kernel modules loaded at boot.
    pub kernel_modules: &'static [&'static str],
    /// The `[Journal]` settings.
    pub journald: &'static [JournaldSetting],
    /// The `tmpfiles.d` entries.
    pub tmpfiles: &'static [TmpfilesEntry],
    /// The search grants of the `tmpfiles.d` file, after its entries.
    pub search_grants: &'static [SearchGrant],
    /// The unattended-upgrades policy.
    pub unattended_upgrades: UnattendedUpgrades,
    /// The agent's directories, each after its parent.
    pub directories: &'static [StateDir],
}

impl HostProfile {
    /// The profile this build of the agent converges hosts to. Version 2
    /// adds the viewer account and its sshd `Match` block (decision F5);
    /// version 1 was never installed on a node. Version 2 also holds the
    /// accounts ([`HostAccount`]), the directory layout and the systemd
    /// units, all added in M4e before any node installed it.
    pub const CURRENT: Self = Self {
        version: HostProfileVersion::new(2),
        sysctls: &[
            Sysctl {
                key: "net.core.default_qdisc",
                value: "fq",
            },
            Sysctl {
                key: "net.ipv4.tcp_congestion_control",
                value: "bbr",
            },
            Sysctl {
                key: "net.ipv4.tcp_slow_start_after_idle",
                value: "0",
            },
            Sysctl {
                key: "net.ipv4.tcp_notsent_lowat",
                value: "131072",
            },
            Sysctl {
                key: "net.core.rmem_max",
                value: "7500000",
            },
            Sysctl {
                key: "net.core.wmem_max",
                value: "7500000",
            },
            // Loose mode: replies arrive on wgexit from arbitrary sources.
            Sysctl {
                key: "net.ipv4.conf.all.rp_filter",
                value: "2",
            },
            Sysctl {
                key: "net.ipv4.conf.default.rp_filter",
                value: "2",
            },
            Sysctl {
                key: "net.ipv4.ip_forward",
                value: "0",
            },
        ],
        kernel_modules: &["tcp_bbr"],
        journald: &[
            JournaldSetting {
                key: "Storage",
                value: "persistent",
            },
            JournaldSetting {
                key: "SystemMaxUse",
                value: "200M",
            },
            JournaldSetting {
                key: "MaxRetentionSec",
                value: "14day",
            },
        ],
        tmpfiles: &[
            TmpfilesEntry {
                kind: TmpfilesType::Directory,
                path: "/run/mooring",
                mode: 0o750,
                user: "root",
                group: STATE_GROUP,
            },
            TmpfilesEntry {
                kind: TmpfilesType::File,
                path: "/run/mooring/gate.lock",
                mode: 0o660,
                user: "root",
                group: STATE_GROUP,
            },
        ],
        // The watch reads when unattended-upgrades last installed from its
        // log's time; Debian keeps that log's directory 0750 root:adm
        // (checked on Debian 13 on 2026-10-23), which the watch may then
        // search, and nothing more.
        search_grants: &[SearchGrant {
            dir: "/var/log/unattended-upgrades",
            user: WATCH_ACCOUNT,
        }],
        unattended_upgrades: UnattendedUpgrades {
            origins: &["origin=Debian,codename=${distro_codename}-security,label=Debian-Security"],
            reboot_time: "20:00",
        },
        // Who writes where (design §11.3): the agent as root everywhere;
        // the watch its view, journal and usage, and the holds (a viewer's
        // stop, a drain that ended); the viewer only the stop request,
        // which the watch removes. So the stop request has a directory of
        // its own, and the viewer can neither write nor remove the holds.
        // The blobs hold the bundle's secrets and are root's alone.
        directories: &[
            StateDir {
                path: "/var/lib/mooring",
                owner: "root",
                group: STATE_GROUP,
                mode: SETGID | 0o750,
            },
            StateDir {
                path: "/var/lib/mooring/blobs",
                owner: "root",
                group: "root",
                mode: 0o700,
            },
            StateDir {
                path: "/var/lib/mooring/txn",
                owner: "root",
                group: STATE_GROUP,
                mode: SETGID | 0o750,
            },
            StateDir {
                path: "/var/lib/mooring/gate",
                owner: WATCH_ACCOUNT,
                group: STATE_GROUP,
                mode: SETGID | 0o750,
            },
            StateDir {
                path: "/var/lib/mooring/stop",
                owner: "root",
                group: STATE_GROUP,
                mode: SETGID | 0o770,
            },
            StateDir {
                path: "/var/lib/mooring/watch",
                owner: WATCH_ACCOUNT,
                group: STATE_GROUP,
                mode: SETGID | 0o750,
            },
            StateDir {
                path: "/var/lib/mooring/usage",
                owner: WATCH_ACCOUNT,
                group: STATE_GROUP,
                mode: SETGID | 0o750,
            },
            StateDir {
                path: ETC_DIR,
                owner: "root",
                group: "root",
                mode: 0o755,
            },
            StateDir {
                path: "/opt/mooring",
                owner: "root",
                group: "root",
                mode: 0o755,
            },
            StateDir {
                path: "/opt/mooring/engines",
                owner: "root",
                group: "root",
                mode: 0o755,
            },
            StateDir {
                path: "/opt/mooring/engines/store",
                owner: "root",
                group: "root",
                mode: 0o755,
            },
            StateDir {
                path: "/opt/mooring/engines/geodata",
                owner: "root",
                group: "root",
                mode: 0o755,
            },
            StateDir {
                path: "/usr/local/lib/mooring",
                owner: "root",
                group: "root",
                mode: 0o755,
            },
            StateDir {
                path: "/usr/local/lib/mooring/agent",
                owner: "root",
                group: "root",
                mode: 0o755,
            },
        ],
    };

    /// The directories the watch may write: its own and those its group
    /// may write, and `/run/mooring` for `gate.lock` (the unit's
    /// `ReadWritePaths`; everything else is read-only to it).
    pub fn watch_writable(&self) -> Vec<&'static str> {
        let mut writable: Vec<&'static str> = self
            .directories
            .iter()
            .filter(|dir| {
                (dir.owner == WATCH_ACCOUNT && dir.mode & 0o200 != 0)
                    || (dir.group == STATE_GROUP && dir.mode & 0o020 != 0)
            })
            .map(|dir| dir.path)
            .collect();
        writable.extend(
            self.tmpfiles
                .iter()
                .filter(|entry| entry.kind == TmpfilesType::Directory)
                .map(|entry| entry.path),
        );
        writable
    }

    /// The value the profile gives `directive`. The match names every
    /// directive, so the drop-in cannot omit one. `AllowUsers` admits
    /// `root` (the bootstrap and ops keys) and [`crate::VIEWER_ACCOUNT`].
    pub const fn sshd_value(&self, directive: SshdDirective) -> &'static str {
        match directive {
            SshdDirective::PasswordAuthentication
            | SshdDirective::KbdInteractiveAuthentication
            | SshdDirective::AllowTcpForwarding
            | SshdDirective::AllowAgentForwarding
            | SshdDirective::AllowStreamLocalForwarding
            | SshdDirective::PermitTunnel
            | SshdDirective::X11Forwarding => "no",
            SshdDirective::PermitRootLogin => "forced-commands-only",
            SshdDirective::AuthenticationMethods => "publickey",
            SshdDirective::MaxAuthTries => "3",
            SshdDirective::AllowUsers => concat!("root ", viewer_account!()),
        }
    }

    /// The lines `sshd -T` prints for `directive` when the profile is in
    /// effect: the keyword in lower case, a space and the value; for
    /// `AllowUsers`, which holds a list, one such line per user, in the
    /// profile's order (OpenSSH's `servconf.c` dumps a string array one
    /// element per line; seen with OpenSSH 10.3p1's `sshd -T` on
    /// 2026-10-09, and checked on Debian's build in L2/L5).
    ///
    /// `AllowUsers` is the one directive here that is not first-match-wins:
    /// every `AllowUsers` line of every included file adds to the list, so
    /// a later drop-in (a provider image's `AllowUsers debian`) admits
    /// another account, and `sshd -T` then prints a third `allowusers`
    /// line. A drift check must therefore compare the exact multiset of
    /// `allowusers` lines `sshd -T` prints with these, never only that
    /// these are present.
    pub fn sshd_effective_lines(&self, directive: SshdDirective) -> Vec<String> {
        let keyword = directive.keyword().to_ascii_lowercase();
        let value = self.sshd_value(directive);
        match directive {
            SshdDirective::AllowUsers => value
                .split(' ')
                .map(|user| format!("{keyword} {user}"))
                .collect(),
            SshdDirective::PasswordAuthentication
            | SshdDirective::KbdInteractiveAuthentication
            | SshdDirective::PermitRootLogin
            | SshdDirective::AuthenticationMethods
            | SshdDirective::AllowTcpForwarding
            | SshdDirective::AllowAgentForwarding
            | SshdDirective::AllowStreamLocalForwarding
            | SshdDirective::PermitTunnel
            | SshdDirective::X11Forwarding
            | SshdDirective::MaxAuthTries => vec![format!("{keyword} {value}")],
        }
    }

    /// The sshd drop-in: every directive once, then the `Match` block that
    /// gives [`crate::VIEWER_ACCOUNT`] its keys file
    /// ([`ManagedFile::ViewerKeys`], root-owned, inside the committed
    /// generation) and forces `serve-ssh --role viewer`, which holds even
    /// for a key line without `command=`. The block ends at the end of the
    /// included file: OpenSSH restores the match state after each included
    /// file (`servconf.c`, `V_10_0_P1`). With OpenSSH 10.3p1, `sshd -T -C
    /// user=…` on 2026-10-09 showed the main file's later lines and a later
    /// drop-in applying to every account, and `root` and any other account
    /// keeping the default `AuthorizedKeysFile` and no `ForceCommand`, so a
    /// viewer key is never read for root; L2/L5 repeat the check on
    /// Debian's build.
    fn sshd_drop_in_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = SshdDirective::ALL
            .iter()
            .map(|directive| format!("{} {}", directive.keyword(), self.sshd_value(*directive)))
            .collect();
        lines.push(format!("Match User {}", HostAccount::Viewer.name()));
        lines.push(format!(
            "\tAuthorizedKeysFile {}",
            ManagedFile::ViewerKeys.path()
        ));
        lines.push(format!("\tForceCommand {}", Role::Viewer.forced_command()));
        lines
    }

    /// The exact contents of `file`, newline-terminated.
    pub fn render(&self, file: HostFile) -> String {
        let mut text = format!(
            "# Managed by Mooring host profile {}. Local changes are overwritten.\n",
            self.version
        );
        let lines: Vec<String> = match file {
            HostFile::Sysctl => self
                .sysctls
                .iter()
                .map(|sysctl| format!("{} = {}", sysctl.key, sysctl.value))
                .collect(),
            HostFile::KernelModules => self
                .kernel_modules
                .iter()
                .map(|module| (*module).to_owned())
                .collect(),
            HostFile::SshdDropIn => self.sshd_drop_in_lines(),
            HostFile::Journald => std::iter::once("[Journal]".to_owned())
                .chain(
                    self.journald
                        .iter()
                        .map(|setting| format!("{}={}", setting.key, setting.value)),
                )
                .collect(),
            HostFile::Tmpfiles => self
                .tmpfiles
                .iter()
                .map(TmpfilesEntry::line)
                .chain(self.search_grants.iter().map(SearchGrant::line))
                .collect(),
            HostFile::UnattendedUpgrades => self.unattended_upgrades_lines(),
            HostFile::XrayUnit => engine_unit(EngineUser::Xray),
            HostFile::Hy2Unit => engine_unit(EngineUser::Hy2),
            HostFile::WatchUnit => self.watch_unit(),
            HostFile::ReflectUnit => reflect_unit(),
            HostFile::RecoverUnit => recover_unit(),
            HostFile::TargetCheckUnit => target_check_unit(),
            HostFile::TargetCheckTimer => target_check_timer(),
            HostFile::TunnelDropIn => vec![
                "[Unit]".to_owned(),
                format!("ConditionPathExists={}", ManagedFile::WgConf.path()),
            ],
        };
        for line in lines {
            text.push_str(&line);
            text.push('\n');
        }
        text
    }

    /// `mooring-watch.service` (design §5.2, §11.3): the only opener of the
    /// gate, with `CAP_NET_ADMIN` only (for `nft` and `wg`), writing only
    /// [`HostProfile::watch_writable`], restarted without limit, and
    /// closing the gate whenever it stops (`ExecStopPost`, run as root).
    fn watch_unit(&self) -> Vec<String> {
        let mut lines = vec![
            "[Unit]".to_owned(),
            "Description=Mooring watch: the gate, accounting and the node's status".to_owned(),
            format!("After=nftables.service {TUNNEL_UNIT}"),
            "StartLimitIntervalSec=0".to_owned(),
            String::new(),
            "[Service]".to_owned(),
            format!("User={WATCH_ACCOUNT}"),
            format!("Group={STATE_GROUP}"),
            format!("ExecStart={AGENT_CURRENT_PATH} watch"),
            format!("ExecStopPost=+{AGENT_CURRENT_PATH} gate-close"),
            "Restart=always".to_owned(),
            "RestartSec=2".to_owned(),
            "AmbientCapabilities=CAP_NET_ADMIN".to_owned(),
            "CapabilityBoundingSet=CAP_NET_ADMIN".to_owned(),
            format!("ReadWritePaths={}", self.watch_writable().join(" ")),
        ];
        lines.extend(hardening());
        lines.extend(install());
        lines
    }

    /// Every profile file with its contents, in [`HostFile::ALL`] order.
    pub fn files(&self) -> Vec<(HostFile, String)> {
        HostFile::ALL
            .iter()
            .map(|file| (*file, self.render(*file)))
            .collect()
    }

    fn unattended_upgrades_lines(&self) -> Vec<String> {
        let policy = &self.unattended_upgrades;
        let mut lines = vec![
            "APT::Periodic::Update-Package-Lists \"1\";".to_owned(),
            "APT::Periodic::Unattended-Upgrade \"1\";".to_owned(),
            "#clear Unattended-Upgrade::Origins-Pattern;".to_owned(),
            "Unattended-Upgrade::Origins-Pattern {".to_owned(),
        ];
        lines.extend(
            policy
                .origins
                .iter()
                .map(|origin| format!("\t\"{origin}\";")),
        );
        lines.push("};".to_owned());
        lines.push("Unattended-Upgrade::Automatic-Reboot \"true\";".to_owned());
        lines.push(format!(
            "Unattended-Upgrade::Automatic-Reboot-Time \"{}\";",
            policy.reboot_time
        ));
        lines
    }
}
