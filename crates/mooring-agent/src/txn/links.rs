// SPDX-License-Identifier: GPL-3.0-or-later

//! Symbolic links replaced with one rename: the swap's (design §11.2 step
//! 4), `current` to the generation and the fixed links into `current`, and
//! the agent's forced command, which an activation and `Bootstrap` switch.

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use mooring_agent_proto::Generation;

use crate::paths::{Paths, generation_name};

/// Makes `link` a symbolic link to `target` with one rename.
pub(crate) fn replace_link(link: &Path, target: &Path) -> io::Result<()> {
    if fs::read_link(link).is_ok_and(|current| current == target) {
        return Ok(());
    }
    let parent = link
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    crate::store::ensure_dir(parent)?;
    let temporary = link.with_extension(format!("swap.{}", std::process::id()));
    let _stale = fs::remove_file(&temporary);
    symlink(target, &temporary)?;
    fs::rename(&temporary, link)?;
    fs::File::open(parent)?.sync_all()
}

/// The swap (design §11.2 step 4): `current` to `gen-<N>`, and the fixed
/// links into `current`. A Debian `/etc/nftables.conf` that is a file, not
/// the link, is kept as `/etc/nftables.conf.pre-mooring` the first time.
pub(crate) fn swap(paths: &Paths, generation: Generation) -> io::Result<()> {
    replace_link(&paths.current(), Path::new(&generation_name(generation)))?;
    fixed_links(paths)
}

fn fixed_links(paths: &Paths) -> io::Result<()> {
    let nft = paths.nft_conf_link();
    if fs::symlink_metadata(&nft).is_ok_and(|meta| meta.file_type().is_file()) {
        let kept = nft.with_extension("conf.pre-mooring");
        if !kept.exists() {
            fs::rename(&nft, &kept)?;
        }
    }
    replace_link(&nft, Path::new("mooring/current/nftables.conf"))?;
    replace_link(
        &paths.wg_conf_link(),
        Path::new("../mooring/current/wgexit.conf"),
    )?;
    replace_link(
        &paths.geodata_link(),
        Path::new("../../../../etc/mooring/current/geodata"),
    )
}
