// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;

use mooring_model::Sha256Digest;

use super::{EnginesError, Lock, Target, compare, outputs_toml, unquote};

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
fn the_repository_lock_pins_go_1_27_3_and_both_engines() {
    let lock = repository_lock();
    assert_eq!(lock.go.version, "go1.27.3");
    assert_eq!(lock.xray.tag, "v26.9.30");
    assert_eq!(lock.sing_box.tag, "v1.14.2");
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
            "[geodata.outputs]",
            "[geodata.outputs]\n\"geoip.dat\" = \"abc\"",
            "sha256",
        ),
        (
            "[xray.outputs]",
            "[xray.outputs]\n\"darwin-arm64\" = \"\"",
            "not one the lock builds",
        ),
        ("prerelease = false", "prerelease = true", "prerelease"),
        ("[geodata]", "[geodata]\nextra = 1", "unknown field"),
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

/// The printed tables, once pasted into the lock, make the build verify;
/// any other digest, or a missing output, does not.
#[test]
fn the_printed_outputs_pin_the_build_exactly() {
    let manifest = manifest();
    assert!(matches!(
        compare(&repository_lock(), &manifest),
        Err(EnginesError::OutputsNotPinned)
    ));
    let printed = outputs_toml(&manifest);
    let pinned_text = text()
        .replacen("[xray.outputs]\n", "", 1)
        .replacen("[sing-box.outputs]\n", "", 1)
        .replacen("[geodata.outputs]", "", 1)
        + "\n"
        + &printed;
    let lock = Lock::parse(&pinned_text).unwrap();
    assert!(compare(&lock, &manifest).is_ok());
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

/// A `go version -m` report of a binary built as the recipe says.
fn report(go: &str, tags: Option<&str>, ldflags: &str) -> String {
    let mut text = format!(
        "/out/linux-amd64/mooring-hy2: {go}\n\
         \tpath\tgithub.com/sagernet/sing-box/cmd/sing-box\n\
         \tmod\tgithub.com/sagernet/sing-box\t(devel)\t\n\
         \tbuild\t-buildmode=exe\n\
         \tbuild\t-compiler=gc\n\
         \tbuild\t-ldflags={ldflags}\n"
    );
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
    // As `debug/buildinfo` quotes a value with spaces and quotes.
    let ldflags = "\"-X 'github.com/sagernet/sing-box/constant.Version=1.14.2' -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=\"";
    let tags = "with_quic,badlinkname,tfogo_checklinkname0";
    let good = report("go1.27.3", Some(tags), ldflags);
    assert_eq!(hy2.check_metadata("go1.27.3", &good), Ok(()));
    for (bad, why) in [
        (report("go1.27.2", Some(tags), ldflags), "another Go"),
        (report("go1.27.3", Some("with_quic"), ldflags), "-tags"),
        (report("go1.27.3", None, ldflags), "-tags"),
        (report("go1.27.3", Some(tags), "\"-s -w\""), "-ldflags"),
        (
            good.replace("CGO_ENABLED=0", "CGO_ENABLED=1"),
            "CGO_ENABLED",
        ),
        (good.replace("\tbuild\t-trimpath=true\n", ""), "-trimpath"),
        (good.replace("GOOS=linux", "GOOS=darwin"), "GOOS"),
    ] {
        let problem = hy2.check_metadata("go1.27.3", &bad).unwrap_err();
        assert!(problem.contains(why), "{why}: {problem}");
    }
    let xray = &lock.builds()[0];
    let xray_report = report(
        "go1.27.3",
        None,
        "\"-X github.com/xtls/xray-core/core.build=v26.9.30 -s -w -buildid=\"",
    );
    assert_eq!(xray.check_metadata("go1.27.3", &xray_report), Ok(()));
    let tagged = report(
        "go1.27.3",
        Some("with_quic"),
        "\"-X github.com/xtls/xray-core/core.build=v26.9.30 -s -w -buildid=\"",
    );
    assert!(
        xray.check_metadata("go1.27.3", &tagged)
            .unwrap_err()
            .contains("tags")
    );
}

#[test]
fn quoted_settings_are_unquoted_as_go_quotes_them() {
    assert_eq!(unquote("plain"), "plain");
    assert_eq!(unquote("\"a b\""), "a b");
    assert_eq!(unquote("\"say \\\"hi\\\"\""), "say \"hi\"");
    assert_eq!(unquote("\"back\\\\slash\\ttab\""), "back\\slash\ttab");
    assert_eq!(unquote("\"unterminated"), "\"unterminated");
}
