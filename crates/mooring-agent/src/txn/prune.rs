// SPDX-License-Identifier: GPL-3.0-or-later

//! Pruning before staging (design §11.2 step 4): the current generation
//! and the [`KEPT_PREVIOUS`] newest before it are kept, with the engine
//! artifacts they use; the rest is removed.

use std::collections::BTreeSet;
use std::fs;
use std::io;

use mooring_agent_proto::{AgentError, BundleHeader, Generation, IoOp};

use super::stage::{self, remove_generation};
use crate::paths::Paths;
use crate::store::io_error;

/// The previous generations kept besides the current one (design §11.2
/// step 4).
const KEPT_PREVIOUS: usize = 2;

/// Keeps the current generation (whose header, read already, is
/// `current_header`) and the [`KEPT_PREVIOUS`] newest before it, and the
/// engine artifacts they use; removes the rest.
pub(super) fn prune(
    paths: &Paths,
    current: Generation,
    current_header: Option<&BundleHeader>,
) -> Result<(), AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    let mut generations: Vec<u64> = match fs::read_dir(paths.etc()) {
        Ok(entries) => entries
            .filter_map(|entry| {
                entry
                    .ok()?
                    .file_name()
                    .to_str()?
                    .strip_prefix("gen-")?
                    .parse()
                    .ok()
            })
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fail(error)),
    };
    generations.sort_unstable_by(|a, b| b.cmp(a));
    let older: Vec<u64> = generations
        .into_iter()
        .filter(|&generation| generation < current.get())
        .collect();
    for generation in older.iter().skip(KEPT_PREVIOUS) {
        remove_generation(paths, Generation::new(*generation))?;
    }
    let mut kept = vec![current_header.cloned()];
    for generation in older.iter().take(KEPT_PREVIOUS) {
        kept.push(stage::installed_header(
            paths,
            Generation::new(*generation),
        )?);
    }
    let used: BTreeSet<String> = kept
        .iter()
        .flatten()
        .flat_map(|header| {
            header
                .engines
                .digests()
                .into_iter()
                .map(ToString::to_string)
        })
        .collect();
    let store = match fs::read_dir(paths.engine_store()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fail(error)),
    };
    for entry in store {
        let entry = entry.map_err(fail)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !used.contains(&name) {
            fs::remove_dir_all(entry.path()).map_err(fail)?;
        }
    }
    Ok(())
}
