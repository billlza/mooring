// SPDX-License-Identifier: GPL-3.0-or-later

//! The host profile (design §8.6): constant host configuration, versioned,
//! compiled into the agent and converged in every transaction. The data and
//! the exact file text live here, once, for the agent and the renderer.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::vps::viewer_account;
use crate::{
    AGENT_CURRENT_PATH, CURRENT_DIR, ETC_DIR, EngineUser, ManagedFile, Role, STATE_GROUP,
    VIEWER_ACCOUNT, WATCH_ACCOUNT,
};

/// A host profile version. `Hello` reports the installed one; `Apply`
/// carries the one a bundle requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostProfileVersion(u32);

impl HostProfileVersion {
    /// Wraps a version number.
    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    /// The version number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for HostProfileVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// One kernel parameter of `/etc/sysctl.d/60-mooring.conf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sysctl {
    /// The dotted key, such as `net.ipv4.tcp_congestion_control`.
    pub key: &'static str,
    /// The value.
    pub value: &'static str,
}

impl Sysctl {
    /// The file under `/proc/sys` that holds the key; the transaction checks
    /// that it exists before staging (§11.2 step 3). The profile's keys have
    /// no component containing a dot, so every dot is a separator.
    pub fn proc_path(&self) -> String {
        format!("/proc/sys/{}", self.key.replace('.', "/"))
    }
}

closed_enum! {
    /// An sshd directive the profile sets in its drop-in. `Hello` reports
    /// those whose effective value (`sshd -T`) differs from the profile.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum SshdDirective {
        /// `PasswordAuthentication`.
        PasswordAuthentication,
        /// `KbdInteractiveAuthentication`.
        KbdInteractiveAuthentication,
        /// `PermitRootLogin`.
        PermitRootLogin,
        /// `AuthenticationMethods`.
        AuthenticationMethods,
        /// `AllowTcpForwarding`.
        AllowTcpForwarding,
        /// `AllowAgentForwarding`.
        AllowAgentForwarding,
        /// `AllowStreamLocalForwarding`.
        AllowStreamLocalForwarding,
        /// `PermitTunnel`.
        PermitTunnel,
        /// `X11Forwarding`.
        X11Forwarding,
        /// `MaxAuthTries`.
        MaxAuthTries,
        /// `AllowUsers`.
        AllowUsers,
    }
}

impl SshdDirective {
    /// The keyword as written in `sshd_config`.
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::PasswordAuthentication => "PasswordAuthentication",
            Self::KbdInteractiveAuthentication => "KbdInteractiveAuthentication",
            Self::PermitRootLogin => "PermitRootLogin",
            Self::AuthenticationMethods => "AuthenticationMethods",
            Self::AllowTcpForwarding => "AllowTcpForwarding",
            Self::AllowAgentForwarding => "AllowAgentForwarding",
            Self::AllowStreamLocalForwarding => "AllowStreamLocalForwarding",
            Self::PermitTunnel => "PermitTunnel",
            Self::X11Forwarding => "X11Forwarding",
            Self::MaxAuthTries => "MaxAuthTries",
            Self::AllowUsers => "AllowUsers",
        }
    }
}

/// One `[Journal]` setting of the journald drop-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournaldSetting {
    /// The `journald.conf` key.
    pub key: &'static str,
    /// The value.
    pub value: &'static str,
}

closed_enum! {
    /// The `tmpfiles.d` entry type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum TmpfilesType {
        /// `d`: create the directory.
        Directory,
        /// `f`: create the file if it does not exist.
        File,
    }
}

/// One line of the `tmpfiles.d` file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TmpfilesEntry {
    /// The entry type.
    pub kind: TmpfilesType,
    /// The absolute path.
    pub path: &'static str,
    /// The permission bits.
    pub mode: u32,
    /// The owning user.
    pub user: &'static str,
    /// The owning group.
    pub group: &'static str,
}

impl TmpfilesEntry {
    /// The entry in `tmpfiles.d(5)` syntax.
    pub fn line(&self) -> String {
        let kind = match self.kind {
            TmpfilesType::Directory => 'd',
            TmpfilesType::File => 'f',
        };
        format!(
            "{kind} {} {:04o} {} {} -",
            self.path, self.mode, self.user, self.group
        )
    }
}

/// A directory a user may search but not list (`a+ <dir> - - - - u:<user>:x`
/// in the `tmpfiles.d` file): it can reach a file whose name it knows, to
/// read its time, but neither list the directory nor read what the file
/// holds unless the file's own mode lets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchGrant {
    /// The directory, which must exist (`systemd-tmpfiles` skips one that
    /// does not, and re-applies the grant at every boot).
    pub dir: &'static str,
    /// The user.
    pub user: &'static str,
}

impl SearchGrant {
    /// The grant in `tmpfiles.d(5)` syntax.
    pub fn line(&self) -> String {
        format!("a+ {} - - - - u:{}:x", self.dir, self.user)
    }
}

/// The unattended-upgrades policy: security updates only, with an automatic
/// reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnattendedUpgrades {
    /// The only `Unattended-Upgrade::Origins-Pattern` entries.
    pub origins: &'static [&'static str],
    /// `Unattended-Upgrade::Automatic-Reboot-Time`, in the host's time
    /// zone, which is UTC on the supported images.
    pub reboot_time: &'static str,
}

closed_enum! {
    /// A file of the host profile, each at a fixed path.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum HostFile {
        /// The kernel parameters.
        Sysctl,
        /// Kernel modules loaded at boot.
        KernelModules,
        /// The sshd drop-in; it must sort before `50-cloud-init.conf`.
        SshdDropIn,
        /// The journald drop-in.
        Journald,
        /// The `tmpfiles.d` entries for `/run/mooring`.
        Tmpfiles,
        /// The unattended-upgrades policy.
        UnattendedUpgrades,
        /// `mooring-xray.service`.
        XrayUnit,
        /// `mooring-hy2.service`.
        Hy2Unit,
        /// `mooring-watch.service`.
        WatchUnit,
        /// `mooring-reflect.service`.
        ReflectUnit,
        /// `mooring-txn-recover.service`, which reverts a change a reboot
        /// left pending (design §11.2).
        RecoverUnit,
        /// A drop-in for Debian's `wg-quick@wgexit.service` that skips the
        /// tunnel until the first `Apply` has installed its configuration.
        TunnelDropIn,
    }
}

impl HostFile {
    /// Where the file is installed.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Sysctl => "/etc/sysctl.d/60-mooring.conf",
            Self::KernelModules => "/etc/modules-load.d/mooring.conf",
            Self::SshdDropIn => "/etc/ssh/sshd_config.d/10-mooring.conf",
            Self::Journald => "/etc/systemd/journald.conf.d/60-mooring.conf",
            Self::Tmpfiles => "/etc/tmpfiles.d/mooring.conf",
            Self::UnattendedUpgrades => "/etc/apt/apt.conf.d/52mooring-unattended-upgrades",
            Self::XrayUnit => "/etc/systemd/system/mooring-xray.service",
            Self::Hy2Unit => "/etc/systemd/system/mooring-hy2.service",
            Self::WatchUnit => "/etc/systemd/system/mooring-watch.service",
            Self::ReflectUnit => "/etc/systemd/system/mooring-reflect.service",
            Self::RecoverUnit => "/etc/systemd/system/mooring-txn-recover.service",
            Self::TunnelDropIn => "/etc/systemd/system/wg-quick@wgexit.service.d/10-mooring.conf",
        }
    }

    /// The file's name in a generation's `host/` directory, where a
    /// transaction stages it (design §11.2 step 2). Two installed files
    /// share a base name (`60-mooring.conf`, `10-mooring.conf`), so each
    /// has its own.
    pub const fn staged_name(self) -> &'static str {
        match self {
            Self::Sysctl => "sysctl.conf",
            Self::KernelModules => "modules-load.conf",
            Self::SshdDropIn => "sshd.conf",
            Self::Journald => "journald.conf",
            Self::Tmpfiles => "tmpfiles.conf",
            Self::UnattendedUpgrades => "unattended-upgrades.conf",
            Self::XrayUnit => "mooring-xray.service",
            Self::Hy2Unit => "mooring-hy2.service",
            Self::WatchUnit => "mooring-watch.service",
            Self::ReflectUnit => "mooring-reflect.service",
            Self::RecoverUnit => "mooring-txn-recover.service",
            Self::TunnelDropIn => "wg-quick-wgexit.conf",
        }
    }

    /// The unit a unit file defines; `None` for every other file (the
    /// tunnel's drop-in only amends Debian's unit).
    pub const fn unit(self) -> Option<&'static str> {
        match self {
            Self::XrayUnit => Some("mooring-xray.service"),
            Self::Hy2Unit => Some("mooring-hy2.service"),
            Self::WatchUnit => Some("mooring-watch.service"),
            Self::ReflectUnit => Some("mooring-reflect.service"),
            Self::RecoverUnit => Some("mooring-txn-recover.service"),
            Self::Sysctl
            | Self::KernelModules
            | Self::SshdDropIn
            | Self::Journald
            | Self::Tmpfiles
            | Self::UnattendedUpgrades
            | Self::TunnelDropIn => None,
        }
    }
}

/// The units the profile enables: its own and the Debian units of the
/// ruleset and the tunnel, which start at boot once a generation has
/// installed their files (the tunnel's drop-in skips it until then).
pub const ENABLED_UNITS: [&str; 7] = [
    "nftables.service",
    TUNNEL_UNIT,
    "mooring-xray.service",
    "mooring-hy2.service",
    "mooring-watch.service",
    "mooring-reflect.service",
    "mooring-txn-recover.service",
];

/// The Debian packages a node needs: installed at first boot by the
/// user-data (design §8.9) and, where there is none, by `Bootstrap`.
pub const PACKAGES: [&str; 5] = [
    "wireguard-tools",
    "nftables",
    "chrony",
    "unattended-upgrades",
    "curl",
];

/// The fixed link Xray's `XRAY_LOCATION_ASSET` names; it points at the
/// current generation's geodata (design §11.2 step 4).
pub const XRAY_ASSET_DIR: &str = "/opt/mooring/engines/geodata/current";

closed_enum! {
    /// An account the host profile creates (design §5.2, §8.6), in the
    /// order `Bootstrap` creates them. None has a home or a password; only
    /// the viewer has a shell, which sshd needs to run its forced command.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum HostAccount {
        /// [`WATCH_ACCOUNT`], the watch unit's user.
        Watch,
        /// [`VIEWER_ACCOUNT`], the remote viewer's login (decision F5,
        /// critique C-9).
        Viewer,
        /// `mooring-xray`, Xray's user.
        Xray,
        /// `mooring-hy2`, Hysteria2's user.
        Hy2,
    }
}

impl HostAccount {
    /// The user name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Watch => WATCH_ACCOUNT,
            Self::Viewer => VIEWER_ACCOUNT,
            Self::Xray => EngineUser::Xray.name(),
            Self::Hy2 => EngineUser::Hy2.name(),
        }
    }

    /// The primary group: [`STATE_GROUP`] for the watch and the viewer,
    /// which read the node's state, and a group of its own, named like
    /// the account, for an engine, so that only it reads its configuration.
    pub const fn group(self) -> &'static str {
        match self {
            Self::Watch | Self::Viewer => STATE_GROUP,
            Self::Xray | Self::Hy2 => self.name(),
        }
    }

    /// The home directory, which does not exist: no account keeps files.
    pub const fn home(self) -> &'static str {
        "/nonexistent"
    }

    /// The login shell. sshd runs the viewer's forced command through it,
    /// so the viewer's must be a real shell (`nologin` would refuse the
    /// command); no other account logs in.
    pub const fn shell(self) -> &'static str {
        match self {
            Self::Viewer => "/bin/sh",
            Self::Watch | Self::Xray | Self::Hy2 => "/usr/sbin/nologin",
        }
    }
}

/// A directory of the agent's layout with its owner, group and mode,
/// which `Bootstrap` creates and sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateDir {
    /// The absolute path.
    pub path: &'static str,
    /// The owning user.
    pub owner: &'static str,
    /// The owning group.
    pub group: &'static str,
    /// The permission bits, set-group-ID included.
    pub mode: u32,
}

/// The set-group-ID bit: files created in such a directory take its group,
/// so what root writes there is readable by [`STATE_GROUP`] too.
pub const SETGID: u32 = 0o2000;

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
        version: HostProfileVersion(2),
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
    /// `root` (the bootstrap and ops keys) and [`VIEWER_ACCOUNT`].
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
    /// gives [`VIEWER_ACCOUNT`] its keys file
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

/// The tunnel's unit, Debian's `wg-quick@.service` for [`crate::WG_INTERFACE`].
const TUNNEL_UNIT: &str = "wg-quick@wgexit.service";

/// The sandbox of the engine, watch and reflector units (design §5.2).
fn hardening() -> Vec<String> {
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
fn install() -> Vec<String> {
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
fn engine_unit(engine: EngineUser) -> Vec<String> {
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
fn reflect_unit() -> Vec<String> {
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

/// `mooring-txn-recover.service` (design §11.2): at boot, after the
/// ruleset, the tunnel and both engines, revert whatever change a reboot
/// left pending (its confirm timer was lost with the reboot).
fn recover_unit() -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
                    .any(|account| account.name() == engine.name()
                        && account.group() == engine.name())
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
            dir("/usr/local/lib/mooring/agent").path
                == AGENT_CURRENT_PATH.rsplit_once('/').unwrap().0
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
    }

    /// Every unit file defines the unit it is named after, every profile
    /// unit is enabled, and the tunnel's names agree with the interface.
    #[test]
    fn the_units_are_named_by_their_files_and_enabled() {
        let units: Vec<&str> = HostFile::ALL
            .iter()
            .filter_map(|file| file.unit())
            .collect();
        for file in HostFile::ALL {
            if let Some(unit) = file.unit() {
                assert_eq!(file.path(), format!("/etc/systemd/system/{unit}"));
                assert_eq!(file.staged_name(), unit);
                assert!(ENABLED_UNITS.contains(&unit), "{unit}");
            }
        }
        assert_eq!(units.len(), 5);
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
}
