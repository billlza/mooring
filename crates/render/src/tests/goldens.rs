// SPDX-License-Identifier: GPL-3.0-or-later

//! Byte-exact render goldens (design §8.1, §9.3 item 3) in
//! `contract/golden/<fixture>/`: every managed file of every node, the
//! Mac exit and prober configs, and the cloud-init user-data of a planned
//! node. A snapshot holds the file without its final newline (insta trims
//! trailing whitespace), so the single newline is asserted separately. The
//! one file that may be empty, `viewer_authorized_keys` with no viewer
//! recorded, has an empty snapshot, and only it may.

use std::collections::BTreeSet;
use std::path::Path;

use mooring_agent_proto::ManagedFile;
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::NodeId;
use mooring_model::secret::SecretRef;
use mooring_model::user::SuspendReason;

use crate::tests::support::{
    HOST_PRIVATE, cloud_init_keys, edit, engines, fixtures, mac_exit, mac_prober, node, planned,
    vps,
};
use crate::vps::{bundle, cloud_init};

/// One rendered file and the golden that pins it.
struct Golden {
    /// The directory under `contract/golden/`.
    directory: String,
    /// The snapshot name, without `.snap`.
    name: String,
    /// What the file is, for the snapshot description.
    what: &'static str,
    /// Whether the file may be empty.
    empty_allowed: bool,
    bytes: Vec<u8>,
}

impl Golden {
    fn new(directory: &str, name: String, what: &'static str, bytes: &[u8]) -> Self {
        Self {
            directory: directory.to_owned(),
            name,
            what,
            empty_allowed: false,
            bytes: bytes.to_vec(),
        }
    }

    fn managed(directory: &str, node: &NodeId, file: ManagedFile, bytes: &[u8]) -> Self {
        Self {
            empty_allowed: may_be_empty(file),
            ..Self::new(
                directory,
                format!("vps-{node}-{}", file.file_name()),
                section(file),
                bytes,
            )
        }
    }

    fn assert(&self) {
        let text = std::str::from_utf8(&self.bytes).expect("rendered files are UTF-8");
        let name = &self.name;
        let body = if text.is_empty() {
            assert!(self.empty_allowed, "{name}: a rendered file is not empty");
            ""
        } else {
            let body = text
                .strip_suffix('\n')
                .expect("a rendered file ends with a newline");
            assert!(
                !body.ends_with(char::is_whitespace),
                "{name}: exactly one final newline"
            );
            body
        };
        let ending = if self.empty_allowed {
            "the file is this text plus one newline, or empty if this text is"
        } else {
            "the file is this text plus one newline"
        };
        assert!(!text.contains('\r'), "{name}: LF line endings");
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path(format!("../../../../contract/golden/{}", self.directory));
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        settings.set_description(format!(
            "SPDX-License-Identifier: GPL-3.0-or-later. mooring-render {}; {ending}.",
            self.what
        ));
        settings.bind(|| insta::assert_snapshot!(name.as_str(), body));
    }
}

const fn section(file: ManagedFile) -> &'static str {
    match file {
        ManagedFile::XrayConfig => "xray.json (design 8.2)",
        ManagedFile::Hy2Config => "hy2.json (design 8.3)",
        ManagedFile::WgConf => "wgexit.conf (design 8.4)",
        ManagedFile::Nftables => "nftables.conf (design 8.5)",
        ManagedFile::WatchConfig => "watch.json (design 11.3)",
        ManagedFile::ViewerKeys => "viewer_authorized_keys (design 15.9)",
    }
}

/// Whether `file` may render to nothing: only the viewer keys, when no
/// viewer is recorded.
const fn may_be_empty(file: ManagedFile) -> bool {
    match file {
        ManagedFile::ViewerKeys => true,
        ManagedFile::XrayConfig
        | ManagedFile::Hy2Config
        | ManagedFile::WgConf
        | ManagedFile::Nftables
        | ManagedFile::WatchConfig => false,
    }
}

/// Every managed file of every node of every fixture.
fn vps_goldens() -> Vec<Golden> {
    let mut goldens = Vec::new();
    for fixture in fixtures() {
        for node in fixture.deployment.nodes().keys() {
            let bundle = vps(&fixture, node);
            for (file, rendered) in bundle.files() {
                goldens.push(Golden::managed(
                    fixture.name,
                    node,
                    file,
                    rendered.expose_bytes(),
                ));
            }
        }
    }
    goldens
}

/// The Mac exit and prober configs of every fixture.
fn mac_goldens() -> Vec<Golden> {
    let mut goldens = Vec::new();
    for fixture in fixtures() {
        goldens.push(Golden::new(
            fixture.name,
            "mac-exit.json".to_owned(),
            "mooring-exit config (design 8.7)",
            mac_exit(&fixture).file().expose_bytes(),
        ));
        goldens.push(Golden::new(
            fixture.name,
            "mac-prober.json".to_owned(),
            "mooring-probe config (design 8.8)",
            mac_prober(&fixture).file().expose_bytes(),
        ));
    }
    goldens
}

/// The user-data of the planned node.
fn cloud_init_goldens() -> Vec<Golden> {
    let user_data = cloud_init(
        &planned().deployment,
        &node("lon1"),
        &cloud_init_keys(HOST_PRIVATE),
    )
    .unwrap();
    vec![Golden::new(
        "cloud-init",
        "cloud-init-lon1.yaml".to_owned(),
        "cloud-init user-data (design 8.9)",
        user_data.expose_bytes(),
    )]
}

#[test]
fn vps_goldens_match() {
    vps_goldens().iter().for_each(Golden::assert);
}

#[test]
fn mac_goldens_match() {
    mac_goldens().iter().for_each(Golden::assert);
}

#[test]
fn cloud_init_golden_matches() {
    cloud_init_goldens().iter().for_each(Golden::assert);
}

/// A suspended user is in no VPS config, yet the state still references
/// its secrets (design §7). The fixtures derive each user's credentials
/// from its number alone, so suspending the second and third users of
/// `1-node-3-users` must render exactly the `1-node-1-user` goldens:
/// `xray.json` and `hy2.json` lose both users, and the other files, which
/// list no users, are unchanged.
#[test]
fn suspended_users_render_the_goldens_of_a_deployment_without_them() {
    let three = mooring_fixtures::one_node_three_users().unwrap();
    let lon1 = node("lon1");
    let suspended: Vec<_> = three.deployment.users().keys().skip(1).cloned().collect();
    assert_eq!(suspended.len(), 2);
    let deployment = edit(&three.deployment, |parts| {
        for user in parts.users.iter_mut().skip(1) {
            user.suspend(SuspendReason::Operator, FIXTURE_NOW).unwrap();
        }
    });
    let rendered = bundle(&deployment, &lon1, &three.secrets, &engines()).unwrap();
    let before = vps(&three, &lon1);
    for (file, bytes) in rendered.files() {
        Golden::managed("1-node-1-user", &lon1, file, bytes.expose_bytes()).assert();
        let lists_users = matches!(file, ManagedFile::XrayConfig | ManagedFile::Hy2Config);
        assert_eq!(
            bytes.expose_bytes() == before.file(file).expose_bytes(),
            !lists_users,
            "{file:?}"
        );
    }
    let required = deployment.required_secrets();
    assert_eq!(required, three.deployment.required_secrets());
    for user in &suspended {
        for secret_ref in [
            SecretRef::UserVlessUuid(user.clone(), lon1.clone()),
            SecretRef::UserLoopUuid(user.clone(), lon1.clone()),
            SecretRef::UserHy2Password(user.clone(), lon1.clone()),
        ] {
            assert!(required.contains(&secret_ref), "{secret_ref}");
        }
    }
}

/// The files of `contract/golden/`, as `(directory, file name)`.
fn golden_directory_files() -> BTreeSet<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/golden");
    let mut files = BTreeSet::new();
    for directory in std::fs::read_dir(root).unwrap() {
        let directory = directory.unwrap();
        let directory_name = directory.file_name().into_string().unwrap();
        for file in std::fs::read_dir(directory.path()).unwrap() {
            let file_name = file.unwrap().file_name().into_string().unwrap();
            files.insert((directory_name.clone(), file_name));
        }
    }
    files
}

/// `contract/golden/` holds exactly the goldens the tests above assert,
/// besides the `export-*` goldens that mooring-export's tests own, so a
/// golden left behind for a removed fixture, node or file fails here
/// (design §16 L2, "a stale golden").
#[test]
fn the_golden_directories_hold_exactly_the_rendered_files() {
    let rendered: BTreeSet<_> = [vps_goldens(), mac_goldens(), cloud_init_goldens()]
        .into_iter()
        .flatten()
        .map(|golden| (golden.directory, format!("{}.snap", golden.name)))
        .collect();
    let found: BTreeSet<_> = golden_directory_files()
        .into_iter()
        .filter(|(_, file)| !file.starts_with("export-"))
        .collect();
    assert_eq!(found, rendered);
}
