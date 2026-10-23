// SPDX-License-Identifier: GPL-3.0-or-later

//! Staging (design §11.2 step 2) and the generation's layout.
//!
//! A generation directory, `/etc/mooring/gen-<N>/` (0755 root, so sshd can
//! read the viewer keys as `mooring-view`, §8.6), holds:
//! - the six managed files under their file names, each copied from its
//!   verified blob (`wgexit.conf` 0600, `viewer_authorized_keys` 0644, the
//!   rest 0640), an engine's configuration in the engine's group and
//!   `watch.json` in the state group, so each is read by its consumer and
//!   no one else;
//! - `host/`, the host profile's files (design §8.6), which the swap
//!   installs;
//! - `bundle.json`, the header it was installed from (its digest answers
//!   the next `Apply` with `Unchanged`);
//! - `engines/xray` and `engines/mooring-hy2`, and `geodata/geoip.dat` and
//!   `geodata/geosite.dat`: links into the engine store,
//!   `/opt/mooring/engines/store/<sha>/<name>`.
//!
//! So one rename of `/etc/mooring/current` switches the configuration, the
//! engines and the geodata together; the fixed links
//! `/opt/mooring/engines/geodata/current` (`XRAY_LOCATION_ASSET`),
//! `/etc/wireguard/wgexit.conf` and `/etc/nftables.conf` point into
//! `current` and never change.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    AgentError, BundleHeader, Generation, HostAccount, HostProfile, IoOp, ManagedFile, Sha256Hex,
};

use crate::blobs::digest_of;
use crate::hostfiles::{self, HOST_DIR};
use crate::paths::Paths;
use crate::store::{io_error, write_json};

/// An engine artifact: its name in the store and the generation, and its
/// mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Artifact {
    /// The file name.
    pub(crate) name: &'static str,
    /// The generation subdirectory its link lives in.
    pub(crate) dir: &'static str,
    /// The file's mode in the store.
    pub(crate) mode: u32,
}

/// The four engine artifacts of a bundle, with their digests.
pub(crate) fn artifacts(header: &BundleHeader) -> [(Artifact, Sha256Hex); 4] {
    let engines = &header.engines;
    [
        (XRAY, engines.xray),
        (HY2, engines.hy2),
        (GEOIP, engines.geoip),
        (GEOSITE, engines.geosite),
    ]
}

/// The Xray binary.
pub(crate) const XRAY: Artifact = Artifact {
    name: "xray",
    dir: "engines",
    mode: 0o755,
};
/// The `mooring-hy2` (sing-box) binary.
pub(crate) const HY2: Artifact = Artifact {
    name: "mooring-hy2",
    dir: "engines",
    mode: 0o755,
};
/// `geoip.dat`.
pub(crate) const GEOIP: Artifact = Artifact {
    name: "geoip.dat",
    dir: "geodata",
    mode: 0o644,
};
/// `geosite.dat`.
pub(crate) const GEOSITE: Artifact = Artifact {
    name: "geosite.dat",
    dir: "geodata",
    mode: 0o644,
};

/// The header's name in a generation directory.
pub(crate) const BUNDLE_FILE: &str = "bundle.json";

/// A managed file's mode in the generation.
pub(crate) const fn file_mode(file: ManagedFile) -> u32 {
    match file {
        ManagedFile::WgConf => 0o600,
        ManagedFile::ViewerKeys => 0o644,
        ManagedFile::XrayConfig
        | ManagedFile::Hy2Config
        | ManagedFile::Nftables
        | ManagedFile::WatchConfig => 0o640,
    }
}

/// The account whose group reads a managed file; the others are root's
/// alone (sshd reads the viewer keys as the viewer, by their 0644 mode).
pub(crate) const fn file_reader(file: ManagedFile) -> Option<HostAccount> {
    match file {
        ManagedFile::XrayConfig => Some(HostAccount::Xray),
        ManagedFile::Hy2Config => Some(HostAccount::Hy2),
        ManagedFile::WatchConfig => Some(HostAccount::Watch),
        ManagedFile::WgConf | ManagedFile::Nftables | ManagedFile::ViewerKeys => None,
    }
}

/// The store path of an artifact.
pub(crate) fn store_path(paths: &Paths, artifact: Artifact, sha256: &Sha256Hex) -> PathBuf {
    paths
        .engine_store()
        .join(sha256.to_string())
        .join(artifact.name)
}

/// A staged program in generation `dir`: `<dir>/engines/<name>`.
pub(crate) fn program(dir: &Path, artifact: Artifact) -> PathBuf {
    dir.join(artifact.dir).join(artifact.name)
}

fn stage_error(error: &io::Error) -> AgentError {
    io_error(IoOp::WriteState, error)
}

/// Stages generation `generation` from the blob store: a fresh directory,
/// every managed file, the header, and the engine artifacts with their
/// links. A directory left by an earlier failed attempt is replaced.
pub(crate) fn stage(
    paths: &Paths,
    generation: Generation,
    header: &BundleHeader,
) -> Result<PathBuf, AgentError> {
    let dir = paths.generation(generation);
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(stage_error(&error)),
    }
    for sub in ["", "engines", "geodata"] {
        let path = dir.join(sub);
        fs::create_dir_all(&path).map_err(|error| stage_error(&error))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|error| stage_error(&error))?;
    }
    for (file, sha256) in header.files.iter() {
        let target = dir.join(file.file_name());
        copy_blob(&paths.blob(sha256), &target, file_mode(file))?;
        if let Some(reader) = file_reader(file) {
            let gid = crate::accounts::primary_group(paths, reader)?;
            std::os::unix::fs::chown(&target, None, Some(gid))
                .map_err(|error| stage_error(&error))?;
        }
    }
    write_json(&dir.join(BUNDLE_FILE), header, 0o644)?;
    hostfiles::stage(&dir.join(HOST_DIR), &HostProfile::CURRENT)?;
    for (artifact, sha256) in artifacts(header) {
        let stored = store_path(paths, artifact, &sha256);
        if !stored_intact(&stored, &sha256)? {
            fs::create_dir_all(paths.engine_store().join(sha256.to_string()))
                .map_err(|error| stage_error(&error))?;
            copy_blob(&paths.blob(&sha256), &stored, artifact.mode)?;
        }
        symlink(&stored, program(&dir, artifact)).map_err(|error| stage_error(&error))?;
    }
    File::open(&dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| stage_error(&error))?;
    Ok(dir)
}

/// Whether the store already holds an intact copy of `sha256` at `path`.
pub(crate) fn stored_intact(path: &Path, sha256: &Sha256Hex) -> Result<bool, AgentError> {
    match File::open(path) {
        Ok(file) => {
            Ok(digest_of(file).map_err(|error| io_error(IoOp::ReadBlob, &error))? == *sha256)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(IoOp::ReadBlob, &error)),
    }
}

/// Copies a verified blob to `target` with `mode`, through a temporary
/// file renamed into place.
pub(crate) fn copy_blob(blob: &Path, target: &Path, mode: u32) -> Result<(), AgentError> {
    let temporary = target.with_extension("staging");
    let copied = (|| {
        let mut source = File::open(blob)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        io::copy(&mut source, &mut file)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, target)
    })();
    if let Err(error) = copied {
        let _absent = fs::remove_file(&temporary);
        return Err(match error.kind() {
            io::ErrorKind::NotFound => io_error(IoOp::ReadBlob, &error),
            _ => stage_error(&error),
        });
    }
    Ok(())
}

/// The header installed with generation `generation`, if its directory
/// holds one.
pub(crate) fn installed_header(
    paths: &Paths,
    generation: Generation,
) -> Result<Option<BundleHeader>, AgentError> {
    if generation == Generation::ZERO {
        return Ok(None);
    }
    crate::store::read_json(&paths.generation(generation).join(BUNDLE_FILE))
}
