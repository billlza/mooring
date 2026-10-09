// SPDX-License-Identifier: GPL-3.0-or-later

//! The host profile (design §8.6): constant host configuration, versioned,
//! compiled into the agent and converged in every transaction. The data and
//! the exact file text live here, once, for the agent and the renderer.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::vps::viewer_account;
use crate::{ManagedFile, Role, VIEWER_ACCOUNT};

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

/// The unprivileged account a remote viewer logs in as (design §15.9,
/// decision F5, critique C-9). The agent converges it (M4); which group
/// lets it read the status, usage and report files is decided with those
/// files' modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewerAccount {
    /// The user name, [`VIEWER_ACCOUNT`].
    pub name: &'static str,
    /// The home directory, which does not exist: the account keeps no
    /// files.
    pub home: &'static str,
    /// The login shell. sshd runs the forced command through it, so it must
    /// be a real shell (`nologin` would refuse the command).
    pub shell: &'static str,
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
    /// The remote viewer's account.
    pub viewer: ViewerAccount,
}

impl HostProfile {
    /// The profile this build of the agent converges hosts to. Version 2
    /// adds the viewer account and its sshd `Match` block (decision F5);
    /// version 1 was never installed on a node.
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
        viewer: ViewerAccount {
            name: VIEWER_ACCOUNT,
            home: "/nonexistent",
            shell: "/bin/sh",
        },
    };

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
        lines.push(format!("Match User {}", self.viewer.name));
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

    const HEADER: &str = "# Managed by Mooring host profile 2. Local changes are overwritten.\n";

    #[test]
    fn the_current_profile_is_version_2() {
        assert_eq!(PROFILE.version, HostProfileVersion::new(2));
        assert_eq!(
            PROFILE.viewer,
            ViewerAccount {
                name: "mooring-view",
                home: "/nonexistent",
                shell: "/bin/sh",
            }
        );
        assert_eq!(PROFILE.viewer.name, VIEWER_ACCOUNT);
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
