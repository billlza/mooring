// SPDX-License-Identifier: GPL-3.0-or-later

//! Running the system tools the encoders are cross-checked against:
//! `/usr/bin/ssh-keygen` (OpenSSH_10.3p1) and `/usr/bin/openssl` (LibreSSL
//! 3.3.6). Design §16 L1 runs these comparisons on the macOS runner, whose
//! tool versions and output formats they were written against, so this
//! module and every test that uses it exist only on macOS.

use std::ffi::OsStr;
use std::process::{Command, Stdio};

/// Runs a system tool by absolute path with empty stdin, requires success
/// and returns its stdout as text. A missing tool fails the test rather than
/// skipping it.
pub(crate) fn run_tool<I, S>(program: &str, args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    String::from_utf8(run_tool_bytes(program, args, &[])).unwrap()
}

/// Runs a system tool by absolute path, feeding `stdin`, requires success
/// and returns its stdout bytes.
pub(crate) fn run_tool_bytes<I, S>(program: &str, args: I, stdin: &[u8]) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_tool_raw(program, args, stdin);
    assert!(
        output.status.success(),
        "{program} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Runs a system tool by absolute path, feeding `stdin`, and returns its
/// whole output without judging the exit status.
pub(crate) fn run_tool_raw<I, S>(program: &str, args: I, stdin: &[u8]) -> std::process::Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    use std::io::Write as _;

    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin).unwrap();
    drop(input);
    child.wait_with_output().unwrap()
}

/// Writes `contents` to a new file with mode 0600, as OpenSSH requires for
/// private keys, and returns its path.
pub(crate) fn write_private_file(
    dir: &std::path::Path,
    name: &str,
    contents: &[u8],
) -> std::path::PathBuf {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let path = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(contents).unwrap();
    file.sync_all().unwrap();
    let mode = file.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{}", path.display());
    path
}
