// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-profile names, scalar types, accounts and file paths.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{EngineUser, STATE_GROUP, VIEWER_ACCOUNT, WATCH_ACCOUNT};

use super::TUNNEL_UNIT;

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
        /// `mooring-target-check.service`, the hourly REALITY target check
        /// (design §11.3), a process of its own so that a target that does
        /// not answer never holds up the watch's loop.
        TargetCheckUnit,
        /// `mooring-target-check.timer`, which runs it every hour.
        TargetCheckTimer,
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
            Self::TargetCheckUnit => "/etc/systemd/system/mooring-target-check.service",
            Self::TargetCheckTimer => "/etc/systemd/system/mooring-target-check.timer",
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
            Self::TargetCheckUnit => "mooring-target-check.service",
            Self::TargetCheckTimer => "mooring-target-check.timer",
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
            Self::TargetCheckUnit => Some("mooring-target-check.service"),
            Self::TargetCheckTimer => Some("mooring-target-check.timer"),
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
pub const ENABLED_UNITS: [&str; 8] = [
    "nftables.service",
    TUNNEL_UNIT,
    "mooring-xray.service",
    "mooring-hy2.service",
    "mooring-watch.service",
    "mooring-reflect.service",
    "mooring-txn-recover.service",
    "mooring-target-check.timer",
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
