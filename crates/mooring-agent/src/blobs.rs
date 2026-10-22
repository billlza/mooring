// SPDX-License-Identifier: GPL-3.0-or-later

//! The content-addressed blob store, `/var/lib/mooring/blobs/<sha256>`
//! (design §11.1): every blob is hashed as it arrives and again whenever it
//! is reported present (Level 1: accidental corruption or the wrong
//! artifact), so a defect leads to a re-upload, never to a skipped one.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use mooring_agent_proto::{AgentError, BlobLen, IoOp, ReadError, Sha256Hex, read_blob};
use sha2::{Digest, Sha256};

use crate::paths::Paths;
use crate::store::{ensure_dir, io_error};

/// The blobs of `wanted` that are stored and hash to their names. A stored
/// blob that does not is removed, so the Mac uploads it again.
pub(crate) fn present(
    paths: &Paths,
    wanted: &BTreeSet<Sha256Hex>,
) -> Result<BTreeSet<Sha256Hex>, AgentError> {
    let mut present = BTreeSet::new();
    for sha256 in wanted {
        let path = paths.blob(sha256);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(IoOp::ReadBlob, &error)),
        };
        if digest_of(file).map_err(|error| io_error(IoOp::ReadBlob, &error))? == *sha256 {
            present.insert(*sha256);
        } else {
            fs::remove_file(&path).map_err(|error| io_error(IoOp::WriteBlob, &error))?;
        }
    }
    Ok(present)
}

/// The SHA-256 of everything `reader` yields.
pub(crate) fn digest_of(mut reader: impl Read) -> io::Result<Sha256Hex> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Sha256Hex::from_bytes(hasher.finalize().into()))
}

/// A sink that hashes what it writes.
struct Hashing<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reads a `PutBlob` payload of `len` bytes from `input` (which must then
/// end) into the store as `sha256`. The payload goes to a temporary file in
/// the store and is renamed into place only once it hashes to `sha256`; a
/// payload that does not is `BlobHash` and leaves nothing behind.
pub(crate) fn put(
    paths: &Paths,
    sha256: Sha256Hex,
    len: BlobLen,
    input: &mut impl BufRead,
) -> Result<(), AgentError> {
    let dir = paths.blobs();
    ensure_dir(&dir).map_err(|error| io_error(IoOp::WriteBlob, &error))?;
    let temporary = dir.join(format!(".{sha256}.{}.partial", std::process::id()));
    let outcome = receive(&temporary, sha256, len, input).and_then(|()| {
        fs::rename(&temporary, paths.blob(&sha256))
            .and_then(|()| File::open(&dir)?.sync_all())
            .map_err(|error| io_error(IoOp::WriteBlob, &error))
    });
    if outcome.is_err() {
        // Nothing else uses this name; a failed removal leaves a file the
        // next upload of the same blob from this process id replaces.
        let _absent = fs::remove_file(&temporary);
    }
    outcome
}

fn receive(
    temporary: &std::path::Path,
    expected: Sha256Hex,
    len: BlobLen,
    input: &mut impl BufRead,
) -> Result<(), AgentError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(temporary)
        .map_err(|error| io_error(IoOp::WriteBlob, &error))?;
    let mut sink = Hashing {
        inner: io::BufWriter::new(file),
        hasher: Sha256::new(),
    };
    read_blob(input, len, &mut sink).map_err(|error: ReadError| error.to_agent_error())?;
    let actual = Sha256Hex::from_bytes(sink.hasher.finalize().into());
    if actual != expected {
        return Err(AgentError::BlobHash { expected, actual });
    }
    let file = sink
        .inner
        .into_inner()
        .map_err(|error| io_error(IoOp::WriteBlob, error.error()))?;
    file.sync_all()
        .map_err(|error| io_error(IoOp::WriteBlob, &error))
}
