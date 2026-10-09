// SPDX-License-Identifier: GPL-3.0-or-later

//! What an `Apply` installs: [`ManagedFile`]s at fixed paths, the engine
//! blobs ([`EngineSet`]) and the [`BundleHeader`] that names them all.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{Generation, HostFacts, HostProfileVersion, Sha256Hex, ValueError};

/// The directory whose `gen-<N>` subdirectories hold each staged generation.
pub const ETC_DIR: &str = "/etc/mooring";

/// The symlink to the committed generation's directory.
pub const CURRENT_DIR: &str = "/etc/mooring/current";

closed_enum! {
    /// A rendered configuration file the agent installs. Requests never
    /// carry paths: each variant maps to fixed paths here, the single source
    /// for the agent and the renderer.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum ManagedFile {
        /// Xray's configuration (`xray.json`).
        XrayConfig,
        /// The Hysteria2 engine's configuration (`hy2.json`).
        Hy2Config,
        /// The `wgexit` WireGuard configuration (`wgexit.conf`).
        WgConf,
        /// The complete nftables ruleset (`nftables.conf`).
        Nftables,
        /// The watch loop's configuration (`watch.json`).
        WatchConfig,
        /// The remote viewers' keys (`viewer_authorized_keys`, design
        /// §15.9): one `restrict,command="… --role viewer"` line per
        /// viewer, and empty when there is none. sshd reads it for
        /// [`crate::VIEWER_ACCOUNT`] through the host profile's `Match`
        /// block; it is root-owned and inside the generation directory, so
        /// the viewer account cannot edit its own keys, and a rollback
        /// restores the matching set.
        ///
        /// sshd opens it as the viewer account, not as root (OpenSSH
        /// `auth2-pubkey.c`, `user_key_allowed2`, drops to the user before
        /// opening the keys file), and with StrictModes checks that it and
        /// every directory above it, the `current` link resolved, are owned
        /// by root or the user and writable by neither group nor others. So
        /// it is installed 0644 `root:root`, and `/etc/mooring` and each
        /// `gen-<N>` are 0755 `root:root` (the secret-bearing files beside
        /// it keep their own 0600 or 0640 modes): a 0600 or 0640 keys file,
        /// or a 0750 generation directory, would refuse every viewer login
        /// (design §8.6; L5 checks it with a real login as the viewer).
        ViewerKeys,
    }
}

impl ManagedFile {
    /// The file's name inside a generation directory
    /// (`/etc/mooring/gen-<N>/<name>`).
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::XrayConfig => "xray.json",
            Self::Hy2Config => "hy2.json",
            Self::WgConf => "wgexit.conf",
            Self::Nftables => "nftables.conf",
            Self::WatchConfig => "watch.json",
            Self::ViewerKeys => "viewer_authorized_keys",
        }
    }

    /// The file inside the committed generation:
    /// `/etc/mooring/current/<name>`.
    pub const fn current_path(self) -> &'static str {
        match self {
            Self::XrayConfig => "/etc/mooring/current/xray.json",
            Self::Hy2Config => "/etc/mooring/current/hy2.json",
            Self::WgConf => "/etc/mooring/current/wgexit.conf",
            Self::Nftables => "/etc/mooring/current/nftables.conf",
            Self::WatchConfig => "/etc/mooring/current/watch.json",
            Self::ViewerKeys => "/etc/mooring/current/viewer_authorized_keys",
        }
    }

    /// The fixed path the file's consumer reads. For `WgConf` and
    /// `Nftables` it is the system path (`wg-quick` and `nftables.service`
    /// read it), installed as a symlink to [`ManagedFile::current_path`];
    /// for the others it is the current path itself (sshd reads
    /// `ViewerKeys` there).
    pub const fn path(self) -> &'static str {
        match self {
            Self::WgConf => "/etc/wireguard/wgexit.conf",
            Self::Nftables => "/etc/nftables.conf",
            Self::XrayConfig | Self::Hy2Config | Self::WatchConfig | Self::ViewerKeys => {
                self.current_path()
            }
        }
    }
}

impl fmt::Display for ManagedFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.file_name())
    }
}

/// The digest of every managed file in a bundle. Every file is mandatory,
/// so a bundle that lacks one cannot be represented. On the wire this is a
/// map from [`ManagedFile`] to digest, keys in [`ManagedFile::ALL`] order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFiles {
    /// [`ManagedFile::XrayConfig`].
    #[serde(rename = "XrayConfig")]
    pub xray_config: Sha256Hex,
    /// [`ManagedFile::Hy2Config`].
    #[serde(rename = "Hy2Config")]
    pub hy2_config: Sha256Hex,
    /// [`ManagedFile::WgConf`].
    #[serde(rename = "WgConf")]
    pub wg_conf: Sha256Hex,
    /// [`ManagedFile::Nftables`].
    #[serde(rename = "Nftables")]
    pub nftables: Sha256Hex,
    /// [`ManagedFile::WatchConfig`].
    #[serde(rename = "WatchConfig")]
    pub watch_config: Sha256Hex,
    /// [`ManagedFile::ViewerKeys`].
    #[serde(rename = "ViewerKeys")]
    pub viewer_keys: Sha256Hex,
}

impl BundleFiles {
    /// Builds the set from a digest for each file.
    pub fn from_fn(mut digest: impl FnMut(ManagedFile) -> Sha256Hex) -> Self {
        Self {
            xray_config: digest(ManagedFile::XrayConfig),
            hy2_config: digest(ManagedFile::Hy2Config),
            wg_conf: digest(ManagedFile::WgConf),
            nftables: digest(ManagedFile::Nftables),
            watch_config: digest(ManagedFile::WatchConfig),
            viewer_keys: digest(ManagedFile::ViewerKeys),
        }
    }

    /// The digest of `file`.
    pub const fn get(&self, file: ManagedFile) -> &Sha256Hex {
        match file {
            ManagedFile::XrayConfig => &self.xray_config,
            ManagedFile::Hy2Config => &self.hy2_config,
            ManagedFile::WgConf => &self.wg_conf,
            ManagedFile::Nftables => &self.nftables,
            ManagedFile::WatchConfig => &self.watch_config,
            ManagedFile::ViewerKeys => &self.viewer_keys,
        }
    }

    /// Every file with its digest, in [`ManagedFile::ALL`] order.
    pub fn iter(&self) -> impl Iterator<Item = (ManagedFile, &Sha256Hex)> {
        ManagedFile::ALL.iter().map(|file| (*file, self.get(*file)))
    }
}

impl TryFrom<&BTreeMap<ManagedFile, Sha256Hex>> for BundleFiles {
    type Error = ValueError;

    /// Fails with [`ValueError::MissingManagedFile`] naming the first absent
    /// file in [`ManagedFile::ALL`] order.
    fn try_from(map: &BTreeMap<ManagedFile, Sha256Hex>) -> Result<Self, Self::Error> {
        let digest = |file| {
            map.get(&file)
                .copied()
                .ok_or(ValueError::MissingManagedFile { file })
        };
        Ok(Self {
            xray_config: digest(ManagedFile::XrayConfig)?,
            hy2_config: digest(ManagedFile::Hy2Config)?,
            wg_conf: digest(ManagedFile::WgConf)?,
            nftables: digest(ManagedFile::Nftables)?,
            watch_config: digest(ManagedFile::WatchConfig)?,
            viewer_keys: digest(ManagedFile::ViewerKeys)?,
        })
    }
}

impl From<&BundleFiles> for BTreeMap<ManagedFile, Sha256Hex> {
    fn from(files: &BundleFiles) -> Self {
        files.iter().map(|(file, digest)| (file, *digest)).collect()
    }
}

/// The engine artifacts a bundle runs, each a content-addressed blob
/// (`/opt/mooring/engines/store/<sha>/`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineSet {
    /// The Xray binary.
    pub xray: Sha256Hex,
    /// The `mooring-hy2` (sing-box) binary.
    pub hy2: Sha256Hex,
    /// `geoip.dat`.
    pub geoip: Sha256Hex,
    /// `geosite.dat`.
    pub geosite: Sha256Hex,
}

impl EngineSet {
    /// The four digests, in field order.
    pub const fn digests(&self) -> [&Sha256Hex; 4] {
        [&self.xray, &self.hy2, &self.geoip, &self.geosite]
    }
}

/// What `Apply` asks the agent to install (design §11.1 and §11.2). The
/// files and engines are blobs the Mac uploaded beforehand with `PutBlob`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleHeader {
    /// The generation this bundle becomes; it must be newer than the node's.
    pub config_generation: Generation,
    /// The renderer's digest of the whole bundle. An `Apply` whose digest
    /// equals the current generation's returns `Unchanged`.
    pub digest: Sha256Hex,
    /// The host facts the bundle was rendered for; the live facts must
    /// equal them (see [`HostFacts::check_live`]).
    pub host_facts: HostFacts,
    /// The host profile the bundle requires.
    pub host_profile_version: HostProfileVersion,
    /// The managed files.
    pub files: BundleFiles,
    /// The engine artifacts.
    pub engines: EngineSet,
}

impl BundleHeader {
    /// Every blob the transaction needs: the managed files and the engines.
    /// This is what the Mac asks about with `HaveBlobs` and what the agent
    /// checks before staging.
    pub fn blobs(&self) -> BTreeSet<Sha256Hex> {
        self.files
            .iter()
            .map(|(_, digest)| *digest)
            .chain(self.engines.digests().into_iter().copied())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Hex {
        Sha256Hex::from_bytes([byte; 32])
    }

    #[test]
    fn every_managed_file_has_distinct_fixed_paths() {
        let names: BTreeSet<_> = ManagedFile::ALL
            .iter()
            .map(|file| file.file_name())
            .collect();
        let current: BTreeSet<_> = ManagedFile::ALL
            .iter()
            .map(|file| file.current_path())
            .collect();
        let paths: BTreeSet<_> = ManagedFile::ALL.iter().map(|file| file.path()).collect();
        assert_eq!(names.len(), ManagedFile::ALL.len());
        assert_eq!(current.len(), ManagedFile::ALL.len());
        assert_eq!(paths.len(), ManagedFile::ALL.len());
        for file in ManagedFile::ALL {
            assert_eq!(
                file.current_path(),
                format!("{CURRENT_DIR}/{}", file.file_name())
            );
            assert!(CURRENT_DIR.starts_with(ETC_DIR));
            assert!(file.path().starts_with('/') && !file.path().contains(".."));
        }
        assert_eq!(ManagedFile::WgConf.path(), "/etc/wireguard/wgexit.conf");
        assert_eq!(ManagedFile::Nftables.path(), "/etc/nftables.conf");
        assert_eq!(
            ManagedFile::XrayConfig.path(),
            "/etc/mooring/current/xray.json"
        );
        assert_eq!(
            ManagedFile::Hy2Config.path(),
            "/etc/mooring/current/hy2.json"
        );
        assert_eq!(
            ManagedFile::WatchConfig.path(),
            "/etc/mooring/current/watch.json"
        );
        assert_eq!(
            ManagedFile::ViewerKeys.path(),
            "/etc/mooring/current/viewer_authorized_keys"
        );
        assert_eq!(ManagedFile::ALL.len(), 6);
    }

    #[test]
    fn bundle_files_encode_exactly_like_the_map() {
        let files = BundleFiles::from_fn(|file| digest(file as u8));
        let map: BTreeMap<ManagedFile, Sha256Hex> = (&files).into();
        assert_eq!(
            serde_json::to_string(&files).unwrap(),
            serde_json::to_string(&map).unwrap()
        );
        assert_eq!(BundleFiles::try_from(&map), Ok(files.clone()));
        for file in ManagedFile::ALL {
            assert_eq!(files.get(*file), &digest(*file as u8));
        }
    }

    #[test]
    fn bundle_files_require_every_file() {
        let full: BTreeMap<_, _> = ManagedFile::ALL
            .iter()
            .map(|file| (*file, digest(1)))
            .collect();
        for missing in ManagedFile::ALL {
            let mut map = full.clone();
            map.remove(missing);
            assert_eq!(
                BundleFiles::try_from(&map),
                Err(ValueError::MissingManagedFile { file: *missing })
            );
            let json = serde_json::to_string(&map).unwrap();
            assert!(
                serde_json::from_str::<BundleFiles>(&json).is_err(),
                "{json}"
            );
        }
    }
}
