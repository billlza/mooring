// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use mooring_model::Sha256Digest;

use super::{
    EnginePatch, EnginesError, Lock, StampCheck, Target, bump_module, check_build_id, compare,
    is_release, outputs_toml, pinned, unquote,
};

/// sing-box's security bumps, as the lock writes them.
const SING_BOX_BUMPS: &str = "security-bumps = [\n    \"golang.org/x/crypto@v0.58.0\",\n    \"golang.org/x/net@v0.61.0\",\n    \"google.golang.org/grpc@v1.84.0\",\n]";

fn repository_lock() -> Lock {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("engines.lock.toml");
    Lock::read(&path).unwrap()
}

fn text() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("engines.lock.toml"),
    )
    .unwrap()
}

#[test]
fn the_repository_lock_pins_go_1_27_3_the_engines_and_the_scanner() {
    let lock = repository_lock();
    assert_eq!(lock.go.version, "go1.27.3");
    assert_eq!(lock.xray.tag, "v26.9.30");
    assert_eq!(lock.sing_box.tag, "v1.14.2");
    assert_eq!(lock.realitlscanner.tag, "v0.2.3");
    assert_eq!(lock.govulncheck.version, "v1.8.0");
}

#[test]
fn every_engine_is_built_for_its_targets_with_its_recipe() {
    let lock = repository_lock();
    let outputs: Vec<String> = lock
        .builds()
        .into_iter()
        .map(|build| build.output)
        .collect();
    assert_eq!(
        outputs,
        [
            "linux-amd64/xray",
            "linux-arm64/xray",
            "darwin-arm64/mooring-exit",
            "linux-amd64/mooring-hy2",
            "linux-arm64/mooring-hy2",
            "darwin-arm64/mooring-probe",
            "darwin-arm64/realitlscanner",
        ]
    );
    let builds = lock.builds();
    let xray = &builds[0];
    assert_eq!(
        xray.args_to(Path::new("/o/xray")),
        [
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-gcflags=all=-l=4",
            "-ldflags=-X github.com/xtls/xray-core/core.build=v26.9.30 -s -w -buildid=",
            "-o",
            "/o/xray",
            "./main",
        ]
    );
    let exit = &builds[2];
    assert_eq!(
        exit.args_to(Path::new("/o/exit")),
        [
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-tags=with_gvisor,with_wireguard,badlinkname,tfogo_checklinkname0",
            "-ldflags=-X 'github.com/sagernet/sing-box/constant.Version=1.14.2' -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=",
            "-o",
            "/o/exit",
            "./cmd/sing-box",
        ]
    );
    assert_eq!(exit.source, "sing-box");
    assert_eq!(exit.module, "github.com/sagernet/sing-box");
    assert_eq!(xray.module, "github.com/xtls/xray-core");
    // The scanner stamps no version: stripped, with an empty build ID, and
    // nothing else in its ldflags.
    let scanner = &builds[6];
    assert_eq!(
        scanner.args_to(Path::new("/o/scanner")),
        [
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-s -w -buildid=",
            "-o",
            "/o/scanner",
            ".",
        ]
    );
    assert_eq!(scanner.source, "realitlscanner");
    assert_eq!(scanner.module, "github.com/xtls/RealiTLScanner");
    assert_eq!(scanner.target, Target::DarwinArm64);
    assert!(scanner.tags.is_empty());
    assert_eq!(scanner.gcflags, None);
    assert_eq!(scanner.version_line, None);
    let env: BTreeMap<String, String> = lock.env(Target::DarwinArm64).into_iter().collect();
    assert_eq!(env["GOOS"], "darwin");
    assert_eq!(env["GOARCH"], "arm64");
    assert_eq!(env["CGO_ENABLED"], "0");
    assert_eq!(env["GOTOOLCHAIN"], "local");
    assert_eq!(env["GOFLAGS"], "-mod=readonly -trimpath");
}

#[test]
fn the_pins_are_printed_for_the_workflow() {
    let pins: BTreeMap<&str, String> = repository_lock().pins().into_iter().collect();
    assert_eq!(pins["GO_VERSION"], "go1.27.3");
    assert_eq!(
        pins["GO_LINUX_AMD64_SHA256"],
        "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
    );
    assert_eq!(
        pins["XRAY_COMMIT"],
        "b26a91de4f3294e26a0ad0a970b81a386a41f789"
    );
    assert_eq!(
        pins["SING_BOX_COMMIT"],
        "af6e64c3b69e6132ebaee0e1a3d24e93903f6709"
    );
    assert_eq!(
        pins["REALITLSCANNER_COMMIT"],
        "e5e114747aa8c6dfa4b394a0782f241bf72bdce6"
    );
    assert_eq!(
        pins["GOVULNCHECK"],
        "golang.org/x/vuln/cmd/govulncheck@v1.8.0"
    );
    assert!(pins["GEODATA_URL"].ends_with("/v26.9.30/Xray-linux-64.zip"));
    assert!(pins.values().all(|value| !value.contains('\n')));
}

#[test]
fn a_lock_that_contradicts_itself_is_refused() {
    let lock = text();
    for (from, to, why) in [
        ("schema = 1", "schema = 2", "schema"),
        (
            "core.build=v26.9.30 -s",
            "core.build=v26.9.29 -s",
            "xray ldflags",
        ),
        (
            "reality-replace-commit = \"e1986a4d31ca",
            "reality-replace-commit = \"e1986a4d31cb",
            "reality-replace",
        ),
        (
            "constant.Version=1.14.2'",
            "constant.Version=1.14.1'",
            "sing-box ldflags",
        ),
        ("sum = \"h1:", "sum = \"h2:", "govulncheck"),
        (
            "linux-amd64-sha256 = \"65efbc80",
            "linux-amd64-sha256 = \"65EFBC80",
            "sha256",
        ),
        (
            "\"geoip.dat\" = \"3cf2236c",
            "\"geoip.dat\" = \"3CF2236C",
            "sha256",
        ),
        (
            "[xray.outputs]",
            "[xray.outputs]\n\"darwin-arm64\" = \"\"",
            "not one the lock builds",
        ),
        ("prerelease = false", "prerelease = true", "prerelease"),
        ("[geodata]", "[geodata]\nextra = 1", "unknown field"),
        (
            r#"security-bumps = ["golang.org/x/net@v0.61.0"]"#,
            r#"security-bumps = ["golang.org/x/net@latest"]"#,
            "security bump",
        ),
        (
            r#"security-bumps = ["golang.org/x/net@v0.61.0"]"#,
            r#"security-bumps = ["golang.org/x/net@v0.0.0-20261009170724-c1d31df183e5"]"#,
            "security bump",
        ),
        (
            r#""golang.org/x/crypto@v0.58.0","#,
            r#""golang.org/x/net@v0.58.0","#,
            "twice",
        ),
        (SING_BOX_BUMPS, "security-bumps = []", "exactly when"),
        (
            r#"patch = "engines/patches/xray-v26.9.30.patch""#,
            r#"patch = """#,
            "REALITY replace",
        ),
        (
            r#"ldflags = "-s -w -buildid=""#,
            r#"ldflags = "-X main.version=v0.2.3 -s -w -buildid=""#,
            "realitlscanner ldflags",
        ),
        (r#"tag = "v0.2.3""#, r#"tag = "main""#, "not a release"),
        (
            r#"tag = "v0.2.3""#,
            r#"tag = "v0.2.3-rc.1""#,
            "not a release",
        ),
        (
            "e5e114747aa8c6dfa4b394a0782f241bf72bdce6\"\nprerelease = false",
            "e5e114747aa8c6dfa4b394a0782f241bf72bdce6\"\nprerelease = true",
            "not a release",
        ),
        (
            "[realitlscanner.outputs]",
            "[realitlscanner.outputs]\n\"linux-amd64\" = \"\"",
            "not one the lock builds",
        ),
        (
            "security-bumps = []",
            r#"security-bumps = ["golang.org/x/sys@v0.49.0"]"#,
            "realitlscanner has a patch exactly when",
        ),
        (
            "security-bumps = []",
            r#"security-bumps = ["golang.org/x/sys@latest"]"#,
            "realitlscanner security bump",
        ),
    ] {
        assert!(lock.contains(from), "{from}");
        let changed = lock.replacen(from, to, 1);
        let error = Lock::parse(&changed).unwrap_err();
        assert!(error.contains(why), "{from}: {error}");
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn manifest() -> BTreeMap<String, Sha256Digest> {
    let lock = repository_lock();
    let mut manifest: BTreeMap<String, Sha256Digest> = lock
        .builds()
        .into_iter()
        .enumerate()
        .map(|(index, build)| (build.output, digest(u8::try_from(index).unwrap())))
        .collect();
    manifest.insert("geodata/geoip.dat".to_owned(), digest(20));
    manifest.insert("geodata/geosite.dat".to_owned(), digest(21));
    manifest
}

/// The lock's text without its output digests: the four output tables
/// stay, empty.
fn unpinned_text() -> String {
    let text = text();
    let mut kept = Vec::new();
    let mut in_outputs = false;
    for line in text.lines() {
        if line.starts_with('[') {
            in_outputs = line.ends_with(".outputs]");
        } else if in_outputs && line.starts_with('"') {
            continue;
        }
        kept.push(line);
    }
    kept.join("\n") + "\n"
}

/// The printed tables, once pasted into a lock without digests, make the
/// build verify; any other digest, or a missing output, does not.
#[test]
fn the_printed_outputs_pin_the_build_exactly() {
    let manifest = manifest();
    let unpinned = Lock::parse(&unpinned_text()).unwrap();
    assert!(matches!(
        compare(&unpinned, &manifest),
        Err(EnginesError::OutputsNotPinned)
    ));
    let printed = outputs_toml(&manifest);
    let pinned_text = unpinned_text()
        .replacen("[xray.outputs]\n", "", 1)
        .replacen("[sing-box.outputs]\n", "", 1)
        .replacen("[geodata.outputs]\n", "", 1)
        .replacen("[realitlscanner.outputs]\n", "", 1)
        + "\n"
        + &printed;
    let lock = Lock::parse(&pinned_text).unwrap();
    assert!(compare(&lock, &manifest).is_ok());
    assert!(
        printed.ends_with(&format!(
            "[realitlscanner.outputs]\n\"darwin-arm64\" = \"{}\"\n",
            manifest["darwin-arm64/realitlscanner"]
        )),
        "{printed}"
    );
    let mut no_scanner = manifest.clone();
    no_scanner.remove("darwin-arm64/realitlscanner");
    assert!(matches!(
        compare(&lock, &no_scanner),
        Err(EnginesError::OutputMissing { .. })
    ));
    let mut changed = manifest.clone();
    changed.insert("linux-amd64/mooring-hy2".to_owned(), digest(99));
    assert!(matches!(
        compare(&lock, &changed),
        Err(EnginesError::Digest { .. })
    ));
    let mut fewer = manifest.clone();
    fewer.remove("darwin-arm64/mooring-probe");
    assert!(matches!(
        compare(&lock, &fewer),
        Err(EnginesError::OutputMissing { .. })
    ));
}

/// A `go version -m` report of a binary built under `-trimpath` from the
/// main module `module`, its settings in cmd/go's order (go1.27.3
/// `src/cmd/go/internal/load/pkg.go`): no `-ldflags`, which cmd/go records
/// only without `-trimpath`.
fn report(go: &str, module: &str, gcflags: Option<&str>, tags: Option<&str>) -> String {
    let mut text = format!(
        "/out/linux-amd64/binary: {go}\n\
         \tpath\t{module}/cmd/binary\n\
         \tmod\t{module}\t(devel)\t\n\
         \tbuild\t-buildmode=exe\n\
         \tbuild\t-compiler=gc\n"
    );
    if let Some(gcflags) = gcflags {
        text.push_str(&format!("\tbuild\t-gcflags={gcflags}\n"));
    }
    if let Some(tags) = tags {
        text.push_str(&format!("\tbuild\t-tags={tags}\n"));
    }
    text.push_str("\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=amd64\n\tbuild\tGOOS=linux\n\tbuild\tGOAMD64=v1\n");
    text
}

#[test]
fn build_information_is_checked_against_the_recipe() {
    let lock = repository_lock();
    let hy2 = lock
        .builds()
        .into_iter()
        .find(|build| build.output == "linux-amd64/mooring-hy2")
        .unwrap();
    let tags = "with_quic,badlinkname,tfogo_checklinkname0";
    let sing_box = "github.com/sagernet/sing-box";
    let good = report("go1.27.3", sing_box, None, Some(tags));
    assert_eq!(hy2.check_metadata("go1.27.3", &good), Ok(()));
    // As `debug/buildinfo` quotes a value with spaces and quotes.
    let ldflags = "\tbuild\t-ldflags=\"-X 'github.com/sagernet/sing-box/constant.Version=1.14.2' -s -w -buildid=\"\n";
    for (bad, why) in [
        (report("go1.27.2", sing_box, None, Some(tags)), "another Go"),
        (
            report(
                "go1.27.3",
                "github.com/sagernet/sing-box2",
                None,
                Some(tags),
            ),
            "main module",
        ),
        (
            good.replace("\tmod\tgithub.com/sagernet/sing-box\t(devel)\t\n", ""),
            "main module",
        ),
        (
            report("go1.27.3", sing_box, None, Some("with_quic")),
            "-tags",
        ),
        (report("go1.27.3", sing_box, None, None), "-tags"),
        (
            report("go1.27.3", sing_box, Some("all=-l=4"), Some(tags)),
            "gcflags",
        ),
        (
            good.replace("\tbuild\t-tags", &format!("{ldflags}\tbuild\t-tags")),
            "-ldflags is recorded",
        ),
        (
            good.replace("CGO_ENABLED=0", "CGO_ENABLED=1"),
            "CGO_ENABLED",
        ),
        (good.replace("\tbuild\t-trimpath=true\n", ""), "-trimpath"),
        (good.replace("GOOS=linux", "GOOS=darwin"), "GOOS"),
        (good.replace("GOARCH=amd64", "GOARCH=arm64"), "GOARCH"),
    ] {
        let problem = hy2.check_metadata("go1.27.3", &bad).unwrap_err();
        assert!(problem.contains(why), "{why}: {problem}");
    }
    let xray = &lock.builds()[0];
    let xray_module = "github.com/xtls/xray-core";
    let xray_report = report("go1.27.3", xray_module, Some("all=-l=4"), None);
    assert_eq!(xray.check_metadata("go1.27.3", &xray_report), Ok(()));
    for (bad, why) in [
        (
            report("go1.27.3", xray_module, Some("all=-l=4"), Some("with_quic")),
            "tags",
        ),
        (report("go1.27.3", xray_module, None, None), "-gcflags"),
        (
            report("go1.27.3", xray_module, Some("all=-l"), None),
            "-gcflags",
        ),
        (
            report(
                "go1.27.3",
                "github.com/sagernet/sing-box",
                Some("all=-l=4"),
                None,
            ),
            "main module",
        ),
    ] {
        let problem = xray.check_metadata("go1.27.3", &bad).unwrap_err();
        assert!(problem.contains(why), "{why}: {problem}");
    }
    let scanner = lock
        .builds()
        .into_iter()
        .find(|build| build.output == "darwin-arm64/realitlscanner")
        .unwrap();
    let scanner_report = report("go1.27.3", "github.com/xtls/RealiTLScanner", None, None)
        .replace("GOARCH=amd64", "GOARCH=arm64")
        .replace("GOOS=linux", "GOOS=darwin");
    assert_eq!(scanner.check_metadata("go1.27.3", &scanner_report), Ok(()));
    for (bad, why) in [
        (
            scanner_report.replace("RealiTLScanner", "realitlscanner"),
            "main module",
        ),
        (scanner_report.replace("GOOS=darwin", "GOOS=linux"), "GOOS"),
        (
            report(
                "go1.27.3",
                "github.com/xtls/RealiTLScanner",
                None,
                Some("with_quic"),
            )
            .replace("GOARCH=amd64", "GOARCH=arm64")
            .replace("GOOS=linux", "GOOS=darwin"),
            "tags",
        ),
    ] {
        let problem = scanner.check_metadata("go1.27.3", &bad).unwrap_err();
        assert!(problem.contains(why), "{why}: {problem}");
    }
}

/// The recipe's `-X` stamps, as each engine's `version` command prints them
/// (Xray `core/core.go`, sing-box `cmd/sing-box/cmd_version.go` at the pinned
/// commits); an unstamped build prints Xray's "Custom" or another version.
#[test]
fn the_version_stamp_is_the_recipes() {
    let builds = repository_lock().builds();
    let xray = &builds[0];
    assert_eq!(
        xray.check_version(
            "Xray 26.9.30 (Xray, Penetrates Everything.) v26.9.30 (go1.27.3 linux/amd64)\n\
             A unified platform for anti-censorship.\n"
        ),
        Ok(())
    );
    let arm = &builds[1];
    assert_eq!(arm.target, Target::LinuxArm64);
    assert_eq!(
        arm.version_line.as_deref(),
        Some("Xray 26.9.30 (Xray, Penetrates Everything.) v26.9.30 (go1.27.3 linux/arm64)")
    );
    for unstamped in [
        "Xray 26.9.30 (Xray, Penetrates Everything.) Custom (go1.27.3 linux/amd64)\n",
        "Xray 26.9.30 (Xray, Penetrates Everything.) v26.9.30 (go1.27.2 linux/amd64)\n",
        "",
    ] {
        let problem = xray.check_version(unstamped).unwrap_err();
        assert!(problem.contains("the recipe stamps"), "{problem}");
    }
    let hy2 = &builds[3];
    assert_eq!(hy2.output, "linux-amd64/mooring-hy2");
    assert_eq!(
        hy2.check_version(
            "sing-box version 1.14.2\n\nEnvironment: go1.27.3 linux/amd64\nCGO: disabled\n"
        ),
        Ok(())
    );
    assert!(hy2.check_version("sing-box version unknown\n").is_err());
    assert!(hy2.check_version("sing-box version 1.14.21\n").is_err());
    // The scanner has no version command: what it prints is no stamp.
    let scanner = &builds[6];
    assert_eq!(scanner.output, "darwin-arm64/realitlscanner");
    let problem = scanner
        .check_version("time=... level=ERROR msg=\"You must specify\"\n")
        .unwrap_err();
    assert!(problem.contains("stamps no version"), "{problem}");
}

/// A stamped binary's `version` runs only on a computer of its target; an
/// unstamped one is never run for it.
#[test]
fn the_stamp_is_checked_only_where_it_can_be() {
    let builds = repository_lock().builds();
    let xray = &builds[0];
    assert_eq!(xray.target, Target::LinuxAmd64);
    assert_eq!(xray.stamp_check(Some(Target::LinuxAmd64)), StampCheck::Run);
    assert_eq!(
        xray.stamp_check(Some(Target::DarwinArm64)),
        StampCheck::OtherComputer
    );
    assert_eq!(xray.stamp_check(None), StampCheck::OtherComputer);
    let scanner = &builds[6];
    for host in [Some(Target::DarwinArm64), Some(Target::LinuxAmd64), None] {
        assert_eq!(scanner.stamp_check(host), StampCheck::Unstamped);
    }
}

#[test]
fn the_build_id_is_empty_as_the_recipe_makes_it() {
    assert_eq!(check_build_id("\n"), Ok(()));
    for report in ["abc/def\n", "", "\n\n"] {
        let problem = check_build_id(report).unwrap_err();
        assert!(problem.contains("-buildid="), "{problem}");
    }
}

#[test]
fn the_hosted_runner_runs_its_own_outputs() {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        assert_eq!(Target::host(), Some(Target::LinuxAmd64));
    }
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        assert_eq!(Target::host(), Some(Target::DarwinArm64));
    }
}

#[test]
fn quoted_settings_are_unquoted_as_go_quotes_them() {
    assert_eq!(unquote("plain"), "plain");
    assert_eq!(unquote("\"a b\""), "a b");
    assert_eq!(unquote("\"say \\\"hi\\\"\""), "say \"hi\"");
    assert_eq!(unquote("\"back\\\\slash\\ttab\""), "back\\slash\ttab");
    assert_eq!(unquote("\"unterminated"), "\"unterminated");
}

/// Each engine's patch is what the lock says: Xray's always, with its
/// REALITY replace and its bumps; sing-box's only while it has bumps.
#[test]
fn the_patches_follow_the_lock() {
    let lock = repository_lock();
    assert_eq!(
        lock.patches(),
        [
            EnginePatch {
                source: "xray",
                replace: Some(
                    "-replace=github.com/xtls/reality=github.com/xtls/reality@v0.0.0-20260908045812-e1986a4d31ca"
                        .to_owned()
                ),
                bumps: vec!["golang.org/x/net@v0.61.0".to_owned()],
                path: "engines/patches/xray-v26.9.30.patch".to_owned(),
                sha256: lock.xray.patch_sha256.clone(),
            },
            EnginePatch {
                source: "sing-box",
                replace: None,
                bumps: vec![
                    "golang.org/x/crypto@v0.58.0".to_owned(),
                    "golang.org/x/net@v0.61.0".to_owned(),
                    "google.golang.org/grpc@v1.84.0".to_owned()
                ],
                path: "engines/patches/sing-box-v1.14.2.patch".to_owned(),
                sha256: lock.sing_box.patch_sha256.clone(),
            },
        ]
    );
    let unbumped = text()
        .replacen(SING_BOX_BUMPS, "security-bumps = []", 1)
        .replacen(
            r#"patch = "engines/patches/sing-box-v1.14.2.patch""#,
            r#"patch = """#,
            1,
        )
        .replacen(
            &format!(r#"patch-sha256 = "{}""#, lock.sing_box.patch_sha256),
            r#"patch-sha256 = """#,
            1,
        );
    let unbumped = Lock::parse(&unbumped).unwrap();
    assert_eq!(
        unbumped
            .patches()
            .iter()
            .map(|patch| patch.source)
            .collect::<Vec<_>>(),
        ["xray"]
    );
    let bumped_scanner = text()
        .replacen(
            "security-bumps = []",
            r#"security-bumps = ["golang.org/x/sys@v0.49.0"]"#,
            1,
        )
        .replacen(
            r#"patch = """#,
            r#"patch = "engines/patches/realitlscanner-v0.2.3.patch""#,
            1,
        );
    let bumped_scanner = Lock::parse(&bumped_scanner).unwrap();
    assert_eq!(
        bumped_scanner.patches().last(),
        Some(&EnginePatch {
            source: "realitlscanner",
            replace: None,
            bumps: vec!["golang.org/x/sys@v0.49.0".to_owned()],
            path: "engines/patches/realitlscanner-v0.2.3.patch".to_owned(),
            sha256: String::new(),
        })
    );
}

#[test]
fn a_release_is_v_major_minor_patch() {
    for release in ["v0.2.3", "v26.9.30", "v1.14.2", "v10.0.0"] {
        assert!(is_release(release), "{release}");
    }
    for other in [
        "0.2.3",
        "v0.2",
        "v0.2.3.4",
        "v0.2.3-rc.1",
        "v0.0.0-20260530000000-e5e114747aa8",
        "v.2.3",
        "v0..3",
        "main",
        "",
        "v0.2.3 ",
    ] {
        assert!(!is_release(other), "{other}");
    }
}

#[test]
fn a_security_bump_is_a_released_module_version() {
    assert_eq!(
        bump_module("golang.org/x/net@v0.61.0"),
        Some("golang.org/x/net")
    );
    assert_eq!(
        bump_module("github.com/sagernet/sing-quic@v0.6.12"),
        Some("github.com/sagernet/sing-quic")
    );
    for bad in [
        "golang.org/x/net@latest",
        "golang.org/x/net@0.61.0",
        "golang.org/x/net@v0.61",
        "golang.org/x/net@v0.61.0-rc.1",
        "golang.org/x/net@v0.0.0-20261009170724-c1d31df183e5",
        "golang.org/x/net v0.61.0",
        "net@v0.61.0",
        "golang.org/x/net@v0.61.0 ",
        "golang.org/x/n et@v0.61.0",
        "@v0.61.0",
    ] {
        assert_eq!(bump_module(bad), None, "{bad}");
    }
}

/// Every output's main package is the one its build compiles, and its
/// govulncheck scan uses the same package, tags and target.
#[test]
fn every_output_builds_and_scans_its_main_package() {
    for build in repository_lock().builds() {
        let package = match build.source {
            "xray" => "./main",
            "sing-box" => "./cmd/sing-box",
            source => {
                assert_eq!(source, "realitlscanner");
                "."
            }
        };
        assert_eq!(build.package, package, "{}", build.output);
        assert_eq!(
            build.args.last().map(String::as_str),
            Some(package),
            "{}",
            build.output
        );
    }
}

/// The repository lock pins every output the lock builds, the geodata
/// included, exactly as the hosted build printed them.
#[test]
fn the_repository_lock_pins_every_output() {
    let lock = repository_lock();
    let outputs: BTreeMap<String, &String> = lock.recorded_outputs().into_iter().collect();
    let mut expected: Vec<String> = lock
        .builds()
        .into_iter()
        .map(|build| build.output)
        .collect();
    expected.extend([
        "geodata/geoip.dat".to_owned(),
        "geodata/geosite.dat".to_owned(),
    ]);
    expected.sort();
    assert_eq!(outputs.keys().cloned().collect::<Vec<_>>(), expected);
    assert_eq!(
        outputs["linux-amd64/xray"],
        "49e1f3b3a0c3c82cbcdb167e0eb604dc7125e7b86927f7431b994d9a8415f5cf"
    );
    assert_eq!(
        outputs["darwin-arm64/mooring-exit"],
        "e0a858dda89aab39298d728158af5d57e255301b5853778a83cf6de650179a8a"
    );
    assert_eq!(
        outputs["darwin-arm64/realitlscanner"],
        "ced247fe7b3976ddb1d60cb48483d22009d41ce405da6d756e9a7ce4fbb7a8bc"
    );
    let manifest: BTreeMap<String, Sha256Digest> = outputs
        .iter()
        .map(|(output, digest)| ((*output).clone(), pinned(digest).unwrap().unwrap()))
        .collect();
    assert!(compare(&lock, &manifest).is_ok());
}
