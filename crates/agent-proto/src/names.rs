// SPDX-License-Identifier: GPL-3.0-or-later

//! Validated text that crosses the wire: host and interface names, kernel
//! identifiers, systemd unit names and OpenSSH keys.
//!
//! Every type here accepts only printable ASCII without spaces, so a value
//! received from a VPS can be displayed or logged without escaping, and none
//! can be mistaken for a command-line option where it becomes an argument.

use crate::macros::text_newtype;

text_newtype!(
    /// A Linux network interface name, as the kernel accepts it
    /// (`dev_valid_name`): 1 to 15 bytes, not `.` or `..`, without `/`, `:`
    /// or whitespace. Restricted further to printable ASCII.
    IfName,
    IfName,
    is_if_name
);

text_newtype!(
    /// A kernel release as `uname -r` prints it, such as `6.12.48+deb13-amd64`:
    /// 1 to 64 printable ASCII characters.
    KernelRelease,
    KernelRelease,
    is_kernel_release
);

text_newtype!(
    /// A kernel identifier read from `/proc/sys`, such as the TCP congestion
    /// control (`bbr`) or the default qdisc (`fq`): 1 to 32 characters of
    /// `[a-z0-9_-]`.
    KernelIdent,
    KernelIdent,
    is_kernel_ident
);

text_newtype!(
    /// A DNS host name in lowercase ASCII LDH form: labels of 1 to 63
    /// lowercase letters, digits and hyphens that neither start nor end with
    /// a hyphen, joined by dots, at most 253 bytes, without a trailing dot,
    /// and with a last label that is not all digits (so no IPv4 literal such
    /// as `169.254.169.254` passes). Exactly the rule of `mooring-model`'s
    /// `DnsName`, which `mooring-render` tests value by value; the agent
    /// re-checks it because the name becomes an argument to `xray tls ping`
    /// and `curl`.
    TargetHost,
    TargetHost,
    is_dns_name
);

text_newtype!(
    /// A systemd unit name such as `mooring-xray.service`: 1 to 255
    /// characters of `[A-Za-z0-9:_.@\-]` (plus `\` escapes), not starting
    /// with `-`.
    UnitName,
    UnitName,
    is_unit_name
);

text_newtype!(
    /// A DNS name taken from a certificate's subject alternative names, as
    /// reported by `xray tls ping`. Certificates may carry wildcards and
    /// names outside LDH, so this only requires 1 to 253 printable ASCII
    /// characters; the Mac compares names exactly.
    CertName,
    CertName,
    is_cert_name
);

text_newtype!(
    /// The `Location` of an HTTP redirect, as `curl -w %{redirect_url}`
    /// prints it: 1 to 2048 printable ASCII characters.
    RedirectUrl,
    RedirectUrl,
    is_redirect_url
);

text_newtype!(
    /// An OpenSSH ed25519 public key in `authorized_keys` form without a
    /// comment: `ssh-ed25519 <base64>`. The base64 part encodes the 51-byte
    /// key blob (`string "ssh-ed25519"`, `string key[32]`), so it is exactly
    /// 68 characters that always begin `AAAAC3NzaC1lZDI1NTE5AAAAI` followed
    /// by one of `A`–`P`. The check is structural and needs no decoder.
    SshEd25519Key,
    SshEd25519Key,
    is_ssh_ed25519_key
);

const MAX_IFNAME_BYTES: usize = 15;
const MAX_KERNEL_RELEASE_BYTES: usize = 64;
const MAX_KERNEL_IDENT_BYTES: usize = 32;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_DNS_LABEL_BYTES: usize = 63;
const MAX_UNIT_NAME_BYTES: usize = 255;
const MAX_REDIRECT_URL_BYTES: usize = 2048;

/// Everything before the first variable base64 character of an ed25519
/// `authorized_keys` line.
const SSH_ED25519_PREFIX: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI";
/// Base64 characters after [`SSH_ED25519_PREFIX`]: 68 in total, 25 fixed.
const SSH_ED25519_VARIABLE_CHARS: usize = 43;

fn is_printable_ascii(text: &str, max_bytes: usize) -> bool {
    (1..=max_bytes).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_if_name(text: &str) -> bool {
    is_printable_ascii(text, MAX_IFNAME_BYTES)
        && text != "."
        && text != ".."
        && !text.contains(['/', ':'])
}

fn is_kernel_release(text: &str) -> bool {
    is_printable_ascii(text, MAX_KERNEL_RELEASE_BYTES)
}

fn is_kernel_ident(text: &str) -> bool {
    (1..=MAX_KERNEL_IDENT_BYTES).contains(&text.len())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn is_dns_name(text: &str) -> bool {
    (1..=MAX_DNS_NAME_BYTES).contains(&text.len())
        && text.split('.').all(is_ldh_label)
        && text
            .rsplit('.')
            .next()
            .is_some_and(|top| !top.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=MAX_DNS_LABEL_BYTES).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

fn is_unit_name(text: &str) -> bool {
    (1..=MAX_UNIT_NAME_BYTES).contains(&text.len())
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_.@-\\".contains(&byte))
}

fn is_cert_name(text: &str) -> bool {
    is_printable_ascii(text, MAX_DNS_NAME_BYTES)
}

fn is_redirect_url(text: &str) -> bool {
    is_printable_ascii(text, MAX_REDIRECT_URL_BYTES)
}

fn is_ssh_ed25519_key(text: &str) -> bool {
    let Some(variable) = text.strip_prefix(SSH_ED25519_PREFIX) else {
        return false;
    };
    let Some((first, rest)) = variable.as_bytes().split_first() else {
        return false;
    };
    variable.len() == SSH_ED25519_VARIABLE_CHARS
        && (b'A'..=b'P').contains(first)
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValueError;

    #[test]
    fn interface_names_follow_the_kernel_rule() {
        for ok in ["eth0", "ens3", "enp1s0", "wgexit", "a", "fifteen-chars-x"] {
            assert!(IfName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "sixteen-chars-xx",
            "eth0:1",
            "a/b",
            "eth 0",
            "eth0\n",
        ] {
            assert_eq!(IfName::new(bad), Err(ValueError::IfName), "{bad:?}");
        }
    }

    #[test]
    fn dns_names_are_ascii_ldh_without_a_trailing_dot() {
        let longest_label = "a".repeat(63);
        let longest_name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(longest_name.len(), 253);
        for ok in [
            "example.com",
            "www.example.com",
            "a",
            "x-1.y2",
            "1a.2b",
            "123.example",
            longest_label.as_str(),
            longest_name.as_str(),
        ] {
            assert!(TargetHost::new(ok).is_ok(), "{ok}");
        }
        let too_long_label = "a".repeat(64);
        let too_long_name = format!("{longest_name}a");
        for bad in [
            "",
            "example.com.",
            ".example.com",
            "a..b",
            "-x.com",
            "x-.com",
            "a_b.com",
            "-o",
            "exämple.com",
            "www.Example.COM",
            "LOCALHOST",
            "169.254.169.254",
            "127.0.0.1",
            "example.123",
            "7",
            too_long_label.as_str(),
            too_long_name.as_str(),
        ] {
            assert_eq!(TargetHost::new(bad), Err(ValueError::TargetHost), "{bad:?}");
        }
    }

    #[test]
    fn kernel_identifiers_are_lowercase_tokens() {
        for ok in ["bbr", "fq", "fq_codel", "pfifo_fast", "cubic"] {
            assert!(KernelIdent::new(ok).is_ok(), "{ok}");
        }
        for bad in ["", "BBR", "fq codel", "bbr\n", &"x".repeat(33)] {
            assert_eq!(
                KernelIdent::new(bad),
                Err(ValueError::KernelIdent),
                "{bad:?}"
            );
        }
        assert!(KernelRelease::new("6.12.48+deb13-amd64").is_ok());
        assert_eq!(KernelRelease::new("6.12 x"), Err(ValueError::KernelRelease));
    }

    /// Each bounded text type accepts exactly its limit and refuses one
    /// byte more, both through `new` and when decoded from JSON.
    #[test]
    fn length_bounds_are_exact() {
        type Check = fn(String) -> Result<(), ValueError>;
        let cases: [(usize, ValueError, Check); 3] = [
            (
                MAX_KERNEL_RELEASE_BYTES,
                ValueError::KernelRelease,
                |text| {
                    KernelRelease::new(text.clone())?;
                    serde_json::from_value::<KernelRelease>(text.into())
                        .map(drop)
                        .map_err(|_| ValueError::KernelRelease)
                },
            ),
            (MAX_REDIRECT_URL_BYTES, ValueError::RedirectUrl, |text| {
                RedirectUrl::new(text.clone())?;
                serde_json::from_value::<RedirectUrl>(text.into())
                    .map(drop)
                    .map_err(|_| ValueError::RedirectUrl)
            }),
            (MAX_DNS_NAME_BYTES, ValueError::CertName, |text| {
                CertName::new(text.clone())?;
                serde_json::from_value::<CertName>(text.into())
                    .map(drop)
                    .map_err(|_| ValueError::CertName)
            }),
        ];
        assert_eq!(
            (
                MAX_KERNEL_RELEASE_BYTES,
                MAX_REDIRECT_URL_BYTES,
                MAX_DNS_NAME_BYTES
            ),
            (64, 2048, 253)
        );
        for (limit, error, check) in cases {
            assert_eq!(check("x".repeat(limit)), Ok(()), "{limit}");
            assert_eq!(
                check("x".repeat(limit + 1)),
                Err(error.clone()),
                "{limit} + 1"
            );
            assert_eq!(check(String::new()), Err(error), "empty");
        }
    }

    #[test]
    fn unit_names_reject_option_lookalikes_and_odd_characters() {
        for ok in [
            "mooring-xray.service",
            "wg-quick@wgexit.service",
            "mooring-txn-7.service",
        ] {
            assert!(UnitName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-x.service",
            "a b.service",
            "a;b.service",
            &"u".repeat(256),
        ] {
            assert_eq!(UnitName::new(bad), Err(ValueError::UnitName), "{bad:?}");
        }
    }

    #[test]
    fn ed25519_keys_are_checked_structurally() {
        // The first two are shapes produced by `ssh-keygen -t ed25519`
        // (throwaway keys); the third has the largest permitted first
        // variable character.
        let boundary = format!("{SSH_ED25519_PREFIX}P{}", "A".repeat(42));
        for ok in [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDovDYBFQ/EJvmYfk0of5lLLTslEzJnEr8ZzZjVXapq4",
            boundary.as_str(),
        ] {
            assert!(SshEd25519Key::new(ok).is_ok(), "{ok}");
        }
        let valid =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH";
        for bad in [
            "",
            "ssh-ed25519",
            &valid[..valid.len() - 1],
            &format!("{valid}A"),
            &format!("{valid} comment"),
            &valid.replace("ssh-ed25519 ", "ssh-rsa "),
            &valid.replacen("AAAAIJ", "AAAAIQ", 1),
            &valid.replacen("lowutH", "lowut=", 1),
            &valid.replacen("lowutH", "lowut-", 1),
        ] {
            assert_eq!(
                SshEd25519Key::new(bad),
                Err(ValueError::SshEd25519Key),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn display_and_serde_use_the_validated_text() {
        let host = TargetHost::new("www.example.com").unwrap();
        assert_eq!(host.to_string(), "www.example.com");
        assert_eq!(
            serde_json::to_string(&host).unwrap(),
            r#""www.example.com""#
        );
        assert_eq!(
            serde_json::from_str::<TargetHost>(r#""www.example.com""#).unwrap(),
            host
        );
        assert!(serde_json::from_str::<TargetHost>(r#""-oProxyCommand=x""#).is_err());
        assert!(CertName::new("*.example.com").is_ok());
        assert_eq!(CertName::new("a b"), Err(ValueError::CertName));
        assert!(RedirectUrl::new("https://www.example.com/").is_ok());
        assert_eq!(RedirectUrl::new(""), Err(ValueError::RedirectUrl));
    }
}
