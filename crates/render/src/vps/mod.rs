// SPDX-License-Identifier: GPL-3.0-or-later

//! The VPS side: one node's bundle of managed files (design §8.2–§8.5) and
//! its cloud-init user-data (§8.9).

mod cloud_init;
pub(crate) mod hy2;
pub(crate) mod nft;
pub(crate) mod served;
pub(crate) mod watch;
pub(crate) mod wg;
pub(crate) mod xray;

use mooring_agent_proto::{
    BundleFiles, BundleHeader, EngineSet, Generation, HostFacts, HostProfile, HostProfileVersion,
    ManagedFile, Sha256Hex,
};
use mooring_model::counters::ConfigGeneration;
use mooring_model::node::{Arch, Node, NodeAddress, NodeSite};
use mooring_model::secret::SecretSnapshot;
use mooring_model::target::TargetSpec;
use mooring_model::{Deployment, NodeId, Sha256Digest};
use sha2::{Digest as _, Sha256};

pub use cloud_init::{CloudInitKeys, OpensshHostKey, UserData, cloud_init};

use crate::encode;
use crate::error::RenderError;
use crate::reach::NodeReach;
use crate::rendered::RenderedFile;
use crate::wire;

/// The engine artifacts shipped for each VPS architecture (the app's
/// `Resources/vps/<arch>/` and geodata, design §5.1). The node's recorded
/// architecture selects one set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EngineCatalog {
    /// x86-64 builds.
    pub amd64: EngineSet,
    /// AArch64 builds.
    pub arm64: EngineSet,
}

impl EngineCatalog {
    /// The set for `arch`.
    #[must_use]
    pub const fn for_arch(&self, arch: Arch) -> &EngineSet {
        match arch {
            Arch::Amd64 => &self.amd64,
            Arch::Arm64 => &self.arm64,
        }
    }
}

/// Every managed file of a bundle; none can be missing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Files {
    xray: RenderedFile,
    hy2: RenderedFile,
    wg: RenderedFile,
    nftables: RenderedFile,
    watch: RenderedFile,
}

impl Files {
    const fn get(&self, file: ManagedFile) -> &RenderedFile {
        match file {
            ManagedFile::XrayConfig => &self.xray,
            ManagedFile::Hy2Config => &self.hy2,
            ManagedFile::WgConf => &self.wg,
            ManagedFile::Nftables => &self.nftables,
            ManagedFile::WatchConfig => &self.watch,
        }
    }
}

/// One node's rendered VPS bundle (design §8.1).
///
/// The digest covers everything an `Apply` installs, so the agent's
/// `Unchanged` short-cut (equal digests) can never skip an engine upgrade
/// or a host-profile change. Each file's own SHA-256 is its engine's config
/// digest, which decides what restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpsBundle {
    node: NodeId,
    config_generation: ConfigGeneration,
    files: Files,
    host_profile: HostProfileVersion,
    engines: EngineSet,
    site: NodeSite,
    digest: Sha256Digest,
}

impl VpsBundle {
    /// The node the bundle is for.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// The deployment generation the bundle was rendered from.
    #[must_use]
    pub const fn config_generation(&self) -> ConfigGeneration {
        self.config_generation
    }

    /// One managed file.
    #[must_use]
    pub const fn file(&self, file: ManagedFile) -> &RenderedFile {
        self.files.get(file)
    }

    /// Every managed file, in `ManagedFile::ALL` order.
    pub fn files(&self) -> impl Iterator<Item = (ManagedFile, &RenderedFile)> {
        ManagedFile::ALL
            .iter()
            .map(|file| (*file, self.files.get(*file)))
    }

    /// The host profile the bundle requires.
    #[must_use]
    pub const fn host_profile(&self) -> HostProfileVersion {
        self.host_profile
    }

    /// The engine artifacts for the node's architecture.
    #[must_use]
    pub const fn engines(&self) -> &EngineSet {
        &self.engines
    }

    /// The node's recorded address and host facts the bundle depends on.
    #[must_use]
    pub const fn site(&self) -> &NodeSite {
        &self.site
    }

    /// The bundle digest (see [`VpsBundle`] and `docs/engines.md`).
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// The `Apply` header for this bundle.
    ///
    /// Its host facts are the node's recorded site, which the bundle was
    /// rendered for (uplink interface, address, architecture, port range),
    /// and, for the facts Mooring does not record, the values in `hello`,
    /// the `Hello` just before this `Apply`. The agent compares them with
    /// its live facts before staging (design §11.2 step 1), so a host that
    /// changed since adoption, such as a renamed NIC, is refused there with
    /// `HostFactsChanged` (or `PortPlanConflict` for the port range).
    pub fn header(&self, hello: &HostFacts) -> Result<BundleHeader, RenderError> {
        Ok(BundleHeader {
            config_generation: Generation::new(self.config_generation.get()),
            digest: Sha256Hex::from_bytes(*self.digest.as_bytes()),
            host_facts: wire::header_facts(&self.site, hello)?,
            host_profile_version: self.host_profile,
            files: BundleFiles::from_fn(|file| self.files.get(file).sha256()),
            engines: self.engines.clone(),
        })
    }
}

const fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::Amd64 => "amd64",
        Arch::Arm64 => "arm64",
    }
}

/// Renders node `node`'s bundle. The node must be adopted or applied and
/// have a REALITY target; `secrets` must hold every secret it serves.
pub fn bundle(
    deployment: &Deployment,
    node: &NodeId,
    secrets: &SecretSnapshot,
    engines: &EngineCatalog,
) -> Result<VpsBundle, RenderError> {
    let node = deployment.node(node)?;
    let inputs = node.apply_inputs()?;
    let site = inputs.site.clone();
    let files = files(deployment, node, &site, inputs.target, secrets)?;
    let engines = engines.for_arch(site.host_facts.arch).clone();
    let host_profile = HostProfile::CURRENT.version;
    let digest = bundle_digest(&files, host_profile, &engines, &site);
    Ok(VpsBundle {
        node: node.id.clone(),
        config_generation: deployment.config_generation(),
        files,
        host_profile,
        engines,
        site,
        digest,
    })
}

fn files(
    deployment: &Deployment,
    node: &Node,
    site: &NodeSite,
    target: &TargetSpec,
    secrets: &SecretSnapshot,
) -> Result<Files, RenderError> {
    let id = &node.id;
    let NodeAddress::Public(vps4) = site.address;
    let served = served::served(deployment, node, secrets)?;
    let reach = NodeReach::of(deployment)?;
    let policy = deployment.policy();
    let xray = xray::config(&xray::XrayInput {
        vps4,
        target,
        private_key: secrets.reality_private(id)?,
        served: &served,
        reach: &reach,
        policy,
    })?;
    let listeners = node
        .ports
        .hy2_listeners()
        .map(|(index, listener)| {
            Ok(hy2::ListenerInput {
                index,
                listener,
                obfs: secrets.hy2_obfs(id, index)?,
            })
        })
        .collect::<Result<Vec<_>, RenderError>>()?;
    let hy2 = hy2::config(&hy2::Hy2Input {
        vps4,
        listeners,
        certificate: &node.hy2.certificate,
        key: secrets.hy2_key(id)?,
        served: &served,
    });
    let wg = wg::WgExitInput {
        index: node.wg_index,
        listen_port: node.ports.wg(),
        private_key: secrets.wg_vps_private(id)?,
        peer: node.wg.mac_pub,
    };
    let nft = nft::NftInput {
        vps4,
        flow_cap: deployment.exit().flow_cap,
        target: target.ipv4(),
        camo_forward: policy.camo_forward,
        wg_port: node.ports.wg(),
        reflector: node.ports.reflector(),
        listeners: node
            .ports
            .hy2_listeners()
            .map(|(_, listener)| nft::ListenerPorts {
                port: listener.port(),
                hop: listener.hop(),
            })
            .collect(),
    };
    Ok(Files {
        xray: RenderedFile::new(encode::json(&xray)?),
        hy2: RenderedFile::new(encode::json(&hy2)?),
        wg: RenderedFile::new(encode::text(|sink| wg::write(&wg, sink))),
        nftables: RenderedFile::new(encode::text(|sink| nft::write(&nft, sink))),
        watch: RenderedFile::new(encode::json(&watch::config(node, target)?)?),
    })
}

/// The bundle digest: SHA-256 over this canonical encoding, every line
/// ending in `\n`:
///
/// ```text
/// mooring-vps-bundle/1
/// host-profile <version>
/// arch <amd64|arm64>
/// uplink <interface name>
/// vps4 <ipv4>
/// ephemeral <first>-<last>
/// engine xray <sha256 hex>
/// engine hy2 <sha256 hex>
/// engine geoip <sha256 hex>
/// engine geosite <sha256 hex>
/// file <name> <byte length>      then the bytes and `\n`, for every
///                                managed file in `ManagedFile::ALL` order
/// ```
///
/// Every variable field is a token without spaces or newlines, or a
/// length-prefixed byte string, so the encoding is injective: equal inputs
/// give equal digests and any change to any byte gives another.
fn bundle_digest(
    files: &Files,
    host_profile: HostProfileVersion,
    engines: &EngineSet,
    site: &NodeSite,
) -> Sha256Digest {
    let facts = &site.host_facts;
    let mut hasher = Sha256::new();
    let mut line = |text: String| {
        hasher.update(text.as_bytes());
        hasher.update(b"\n");
    };
    line("mooring-vps-bundle/1".to_owned());
    line(format!("host-profile {host_profile}"));
    line(format!("arch {}", arch_name(facts.arch)));
    line(format!("uplink {}", facts.uplink_interface));
    line(format!("vps4 {}", site.address.ipv4()));
    line(format!("ephemeral {}", facts.ephemeral_ports));
    for (name, digest) in [
        ("xray", &engines.xray),
        ("hy2", &engines.hy2),
        ("geoip", &engines.geoip),
        ("geosite", &engines.geosite),
    ] {
        line(format!("engine {name} {digest}"));
    }
    for file in ManagedFile::ALL {
        let bytes = files.get(*file).expose_bytes();
        hasher.update(format!("file {} {}\n", file.file_name(), bytes.len()).as_bytes());
        hasher.update(bytes);
        hasher.update(b"\n");
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) mod testing {
    //! Crate-internal hooks for the bundle tests.

    use super::*;

    /// The digest of `bundle` with `file` replaced by `bytes`.
    pub(crate) fn digest_with(
        bundle: &VpsBundle,
        file: ManagedFile,
        bytes: Vec<u8>,
    ) -> Sha256Digest {
        digest_with_files(bundle, vec![(file, bytes)])
    }

    /// The digest of `bundle` with each listed file replaced.
    pub(crate) fn digest_with_files(
        bundle: &VpsBundle,
        replacements: Vec<(ManagedFile, Vec<u8>)>,
    ) -> Sha256Digest {
        let mut files = bundle.files.clone();
        for (file, bytes) in replacements {
            let replaced = RenderedFile::new(zeroize::Zeroizing::new(bytes));
            match file {
                ManagedFile::XrayConfig => files.xray = replaced,
                ManagedFile::Hy2Config => files.hy2 = replaced,
                ManagedFile::WgConf => files.wg = replaced,
                ManagedFile::Nftables => files.nftables = replaced,
                ManagedFile::WatchConfig => files.watch = replaced,
            }
        }
        bundle_digest(&files, bundle.host_profile, &bundle.engines, &bundle.site)
    }
}
