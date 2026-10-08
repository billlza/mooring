// SPDX-License-Identifier: GPL-3.0-or-later

//! Cross-checks against `/usr/bin/ssh-keygen` (OpenSSH_10.3p1), which design
//! §16 L1 runs on the macOS runner only: the `-l` output format, in
//! particular the comment field of a private key without a `.pub` file, is
//! the one that release prints.

use std::path::Path;

use super::*;
use crate::testing::tools::{run_tool, run_tool_raw, write_private_file};

const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The `bits SHA256:… comment (ED25519)` fields `ssh-keygen -l` prints.
fn keygen_fingerprint(path: &Path) -> (String, String) {
    let output = run_tool(SSH_KEYGEN, ["-l", "-E", "sha256", "-f", path_str(path)]);
    let fields: Vec<&str> = output.trim_end().split(' ').collect();
    assert_eq!(fields.first(), Some(&"256"), "{output}");
    assert_eq!(fields.last(), Some(&"(ED25519)"), "{output}");
    (fields[1].to_owned(), fields[2..fields.len() - 1].join(" "))
}

/// `ssh-keygen -y` recovers the public line from our file and `-l` prints
/// our fingerprint, for every padding length.
#[test]
fn ssh_keygen_reads_our_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    for (index, text) in PADDING_COMMENTS.iter().enumerate() {
        let pair = SshKeyPair::generate().unwrap();
        let note = comment(text);
        let file = pair.openssh_private_key(&note).unwrap();
        let path = write_private_file(
            dir.path(),
            &format!("key{index}"),
            file.expose_pem().as_bytes(),
        );

        let line = run_tool(SSH_KEYGEN, ["-y", "-f", path_str(&path)]);
        assert_eq!(line, format!("{}\n", pair.public().line(&note)));

        // With no `.pub` beside the file, `-l` prints the private key's own
        // comment, an empty field when there is none.
        let (fingerprint, shown_comment) = keygen_fingerprint(&path);
        assert_eq!(fingerprint, pair.public().fingerprint().to_string());
        assert_eq!(shown_comment, *text);
    }
}

/// A key `ssh-keygen` generated, re-encoded from its own seed and check
/// integer, is byte-for-byte the file `ssh-keygen` wrote.
#[test]
fn our_encoding_is_byte_identical_to_ssh_keygen() {
    let dir = tempfile::tempdir().unwrap();
    for (index, text) in ["", "abcde", "probe@test"].into_iter().enumerate() {
        let path = dir.path().join(format!("theirs{index}"));
        run_tool(
            SSH_KEYGEN,
            [
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                text,
                "-f",
                path_str(&path),
            ],
        );
        let theirs = std::fs::read_to_string(&path).unwrap();
        let decoded = decode(&theirs);
        assert_eq!(decoded.check[0], decoded.check[1]);
        let pair = SshKeyPair::from_seed(Ed25519Seed::from_bytes(decoded.seed).unwrap()).unwrap();
        assert_eq!(*pair.public().key().as_bytes(), decoded.public);
        let ours = pair.encode_private_key(&comment(text), decoded.check[0]);
        assert_eq!(ours.expose_pem(), theirs, "comment {text:?}");
    }
}

/// Parser-free check of a key `ssh-keygen` generated: its public line comes
/// from `ssh-keygen -y`, and our encodings of that public key match
/// `ssh-keygen -y` and `ssh-keygen -l`.
#[test]
fn our_fingerprint_matches_ssh_keygen_for_its_own_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id_ed25519");
    run_tool(
        SSH_KEYGEN,
        [
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            path_str(&path),
        ],
    );
    let line = run_tool(SSH_KEYGEN, ["-y", "-f", path_str(&path)]);
    let encoded = line.trim_end().strip_prefix("ssh-ed25519 ").unwrap();
    let blob = STANDARD.decode(encoded).unwrap();
    let public = SshPublicKey::new(Ed25519Pub::from_ssh_blob(&blob).unwrap());

    assert_eq!(public.authorized_key(), line.trim_end());
    let (fingerprint, _) = keygen_fingerprint(&path);
    assert_eq!(public.fingerprint().to_string(), fingerprint);
    let public_file = dir.path().join("id_ed25519.pub");
    let (fingerprint, _) = keygen_fingerprint(&public_file);
    assert_eq!(public.fingerprint().to_string(), fingerprint);
}

/// `ssh-keygen -F` finds our `known_hosts` line by its address only, and
/// `ssh-keygen -l` prints our fingerprint for it.
#[test]
fn ssh_keygen_finds_our_known_hosts_line() {
    let dir = tempfile::tempdir().unwrap();
    let public = SshKeyPair::generate().unwrap().public();
    let host = Ipv4Addr::new(203, 0, 113, 7);
    let line = public.known_hosts_line(host);
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, format!("{line}\n")).unwrap();

    let found = run_tool(SSH_KEYGEN, ["-F", "203.0.113.7", "-f", path_str(&path)]);
    assert!(found.lines().any(|candidate| candidate == line), "{found}");

    let missing = run_tool_raw(
        SSH_KEYGEN,
        ["-F", "203.0.113.8", "-f", path_str(&path)],
        &[],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty());

    let (fingerprint, shown_host) = keygen_fingerprint(&path);
    assert_eq!(fingerprint, public.fingerprint().to_string());
    assert_eq!(shown_host, "203.0.113.7");
}
