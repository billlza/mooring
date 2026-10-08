// SPDX-License-Identifier: GPL-3.0-or-later

//! The host profile (design §8.6): constant host configuration, versioned,
//! compiled into the agent and converged in every transaction. The data and
//! the exact file text live here, once, for the agent and the renderer.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;

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
        }
    }
}

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
    /// The unattended-upgrades policy.
    pub unattended_upgrades: UnattendedUpgrades,
}

impl HostProfile {
    /// The profile this build of the agent converges hosts to.
    pub const CURRENT: Self = Self {
        version: HostProfileVersion(1),
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
                group: "mooring",
            },
            TmpfilesEntry {
                kind: TmpfilesType::File,
                path: "/run/mooring/gate.lock",
                mode: 0o660,
                user: "root",
                group: "mooring",
            },
        ],
        unattended_upgrades: UnattendedUpgrades {
            origins: &["origin=Debian,codename=${distro_codename}-security,label=Debian-Security"],
            reboot_time: "20:00",
        },
    };

    /// The value the profile gives `directive`. The match names every
    /// directive, so the drop-in cannot omit one.
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
            SshdDirective::AllowUsers => "root",
        }
    }

    /// The line `sshd -T` prints for `directive` when the profile is in
    /// effect: the keyword in lower case, a space and the value.
    pub fn sshd_effective_line(&self, directive: SshdDirective) -> String {
        format!(
            "{} {}",
            directive.keyword().to_ascii_lowercase(),
            self.sshd_value(directive)
        )
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
            HostFile::SshdDropIn => SshdDirective::ALL
                .iter()
                .map(|directive| format!("{} {}", directive.keyword(), self.sshd_value(*directive)))
                .collect(),
            HostFile::Journald => std::iter::once("[Journal]".to_owned())
                .chain(
                    self.journald
                        .iter()
                        .map(|setting| format!("{}={}", setting.key, setting.value)),
                )
                .collect(),
            HostFile::Tmpfiles => self.tmpfiles.iter().map(TmpfilesEntry::line).collect(),
            HostFile::UnattendedUpgrades => self.unattended_upgrades_lines(),
        };
        for line in lines {
            text.push_str(&line);
            text.push('\n');
        }
        text
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

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: HostProfile = HostProfile::CURRENT;

    #[test]
    fn the_current_profile_is_version_1() {
        assert_eq!(PROFILE.version, HostProfileVersion::new(1));
    }

    #[test]
    fn sysctl_file_carries_the_section_8_6_values() {
        assert_eq!(
            PROFILE.render(HostFile::Sysctl),
            "# Managed by Mooring host profile 1. Local changes are overwritten.\n\
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

    #[test]
    fn sshd_drop_in_sets_every_directive_once() {
        assert_eq!(
            PROFILE.render(HostFile::SshdDropIn),
            "# Managed by Mooring host profile 1. Local changes are overwritten.\n\
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
             AllowUsers root\n"
        );
        assert_eq!(
            PROFILE.sshd_effective_line(SshdDirective::PermitRootLogin),
            "permitrootlogin forced-commands-only"
        );
        assert!(HostFile::SshdDropIn.path() < "/etc/ssh/sshd_config.d/50-cloud-init.conf");
    }

    #[test]
    fn the_other_files_have_their_fixed_text() {
        let header = "# Managed by Mooring host profile 1. Local changes are overwritten.\n";
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
                "{header}d /run/mooring 0750 root mooring -\nf /run/mooring/gate.lock 0660 root mooring -\n"
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
    }
}
