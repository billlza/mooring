// SPDX-License-Identifier: GPL-3.0-or-later

//! `clean`: runs `cargo clean` and reports the bytes it freed.
//!
//! The freed amount is the allocated size (`st_blocks`) of the target and
//! build directories before cleaning, counting hard-linked files once (on
//! Linux cargo hard-links final binaries into `target/<profile>/`). On macOS
//! cargo copies them instead, as APFS clones that share their blocks with
//! the original but have their own inode, so there the figure can overstate
//! the space freed. After `cargo clean` both directories must be gone;
//! anything left is an error, not a smaller number.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::cargo::{Cargo, CommandError};
use crate::metadata::{self, MetadataError};
use crate::output::{OutputError, say};

/// `st_blocks` is in 512-byte units on Linux and macOS.
const BLOCK_SIZE: u64 = 512;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CleanError {
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("failed to measure {}", path.display())]
    Measure {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} still exists after cargo clean", path.display())]
    NotRemoved { path: PathBuf },
}

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), CleanError> {
    let metadata = metadata::load(cargo, &["--no-deps"])?;
    let roots = distinct_roots([metadata.target_directory, metadata.build_directory]);
    let mut seen = BTreeSet::new();
    let mut freed = 0_u64;
    for root in &roots {
        freed += allocated_bytes(root, &mut seen)?;
    }

    cargo.run(&["clean", "--locked"])?;

    for root in &roots {
        match fs::symlink_metadata(root) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(CleanError::NotRemoved { path: root.clone() }),
            Err(source) => {
                return Err(CleanError::Measure {
                    path: root.clone(),
                    source,
                });
            }
        }
    }
    let shown: Vec<String> = roots
        .iter()
        .map(|root| root.display().to_string())
        .collect();
    say!(
        out,
        "clean: removed {}; freed {freed} bytes ({:.1} MiB)",
        shown.join(" and "),
        mebibytes(freed)
    )?;
    Ok(())
}

/// Drops duplicates and directories nested in another listed directory.
fn distinct_roots(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let dirs: BTreeSet<PathBuf> = dirs.into_iter().collect();
    dirs.iter()
        .filter(|dir| {
            !dirs
                .iter()
                .any(|other| other != *dir && dir.starts_with(other))
        })
        .cloned()
        .collect()
}

fn mebibytes(bytes: u64) -> f64 {
    // Display only; precision loss above 2^53 bytes is irrelevant here.
    bytes as f64 / (1024.0 * 1024.0)
}

/// Allocated bytes under `path` (0 if it does not exist), without following
/// symbolic links; inodes already in `seen` are not counted again.
fn allocated_bytes(path: &Path, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64, CleanError> {
    let measure_error = |source| CleanError::Measure {
        path: path.to_path_buf(),
        source,
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(source) => return Err(measure_error(source)),
    };
    let mut total = if seen.insert((metadata.dev(), metadata.ino())) {
        metadata.blocks() * BLOCK_SIZE
    } else {
        0
    };
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(measure_error)? {
            total += allocated_bytes(&entry.map_err(measure_error)?.path(), seen)?;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use super::{BLOCK_SIZE, allocated_bytes, distinct_roots};
    use crate::testing::Scratch;

    fn blocks(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().blocks() * BLOCK_SIZE
    }

    #[test]
    fn counts_every_file_and_directory_once_and_hard_links_once() {
        let scratch = Scratch::new("usage");
        let root = &scratch.0;
        let nested = root.join("debug/deps");
        fs::create_dir_all(&nested).unwrap();
        let binary = nested.join("tool-0123");
        fs::write(&binary, vec![7_u8; 64 * 1024]).unwrap();
        fs::hard_link(&binary, root.join("debug/tool")).unwrap();
        fs::write(root.join("CACHEDIR.TAG"), b"Signature").unwrap();

        let expected = [
            root.clone(),
            root.join("debug"),
            nested.clone(),
            binary.clone(),
            root.join("CACHEDIR.TAG"),
        ]
        .iter()
        .map(|path| blocks(path))
        .sum::<u64>();
        assert!(blocks(&binary) >= 64 * 1024, "the file must be allocated");
        assert_eq!(
            allocated_bytes(root, &mut BTreeSet::new()).unwrap(),
            expected
        );
    }

    #[test]
    fn a_missing_directory_frees_nothing() {
        let scratch = Scratch::new("missing");
        assert_eq!(
            allocated_bytes(&scratch.0.join("target"), &mut BTreeSet::new()).unwrap(),
            0
        );
    }

    #[test]
    fn nested_or_repeated_roots_are_measured_once() {
        let roots = distinct_roots([
            PathBuf::from("/w/target"),
            PathBuf::from("/w/target/build"),
            PathBuf::from("/w/target"),
            PathBuf::from("/w/build"),
        ]);
        assert_eq!(
            roots,
            [PathBuf::from("/w/build"), PathBuf::from("/w/target")]
        );
    }
}
