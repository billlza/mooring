// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the agent keeps its state and reads the host (design §5.2, §11).
//! Every path is fixed; a request never names one. Tests root the same
//! layout in a scratch directory.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use mooring_agent_proto::{
    AGENT_CURRENT_PATH, CURRENT_DIR, ETC_DIR, Generation, HostFile, IfName, ManagedFile, Sha256Hex,
    UsageMonth, WG_INTERFACE, XRAY_ASSET_DIR,
};

/// The agent's state directory.
const VAR_LIB: &str = "/var/lib/mooring";
/// The agent's runtime directory (locks).
const RUN: &str = "/run/mooring";
/// The installed agents (design §5.2).
const AGENT_DIR: &str = "/usr/local/lib/mooring/agent";

/// A generation's directory name, `gen-<N>`.
pub(crate) fn generation_name(generation: Generation) -> String {
    format!("gen-{}", generation.get())
}

/// The fixed layout, under a root that is `/` on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Paths {
    root: PathBuf,
}

impl Paths {
    /// The layout of a node.
    #[cfg(target_os = "linux")]
    pub(crate) fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    /// The same layout under `root` (tests).
    #[cfg(test)]
    pub(crate) fn under(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// `absolute`, under the root.
    pub(crate) fn at(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// `/var/lib/mooring`.
    pub(crate) fn var_lib(&self) -> PathBuf {
        self.at(VAR_LIB)
    }

    /// The content-addressed blob store, `/var/lib/mooring/blobs`.
    pub(crate) fn blobs(&self) -> PathBuf {
        self.var_lib().join("blobs")
    }

    /// The blob with digest `sha256`.
    pub(crate) fn blob(&self, sha256: &Sha256Hex) -> PathBuf {
        self.blobs().join(sha256.to_string())
    }

    /// The gate's directory, `/var/lib/mooring/gate`.
    pub(crate) fn gate_dir(&self) -> PathBuf {
        self.var_lib().join("gate")
    }

    /// The holds, `/var/lib/mooring/gate/holds.json` (design §11.3).
    pub(crate) fn holds(&self) -> PathBuf {
        self.gate_dir().join("holds.json")
    }

    /// The directory the viewer may write, `/var/lib/mooring/stop`: its
    /// emergency stop alone, so it never reaches the holds (design §11.3).
    pub(crate) fn stop_dir(&self) -> PathBuf {
        self.var_lib().join("stop")
    }

    /// A viewer's emergency stop, handed to the watch:
    /// `/var/lib/mooring/stop/request.json` (design §11.3).
    pub(crate) fn stop_request(&self) -> PathBuf {
        self.stop_dir().join("request.json")
    }

    /// The halt marker, `/var/lib/mooring/halted.json`.
    pub(crate) fn halted(&self) -> PathBuf {
        self.var_lib().join("halted.json")
    }

    /// The installed host profile version,
    /// `/var/lib/mooring/host-profile.json`.
    pub(crate) fn host_profile(&self) -> PathBuf {
        self.var_lib().join("host-profile.json")
    }

    /// The Mac's latest report for viewers, `/var/lib/mooring/mac-report.json`.
    pub(crate) fn mac_report(&self) -> PathBuf {
        self.var_lib().join("mac-report.json")
    }

    /// The lock that serialises holds and gate changes,
    /// `/run/mooring/gate.lock`.
    pub(crate) fn gate_lock(&self) -> PathBuf {
        self.at(RUN).join("gate.lock")
    }

    /// The current generation's link, `/etc/mooring/current`.
    pub(crate) fn current(&self) -> PathBuf {
        self.at(CURRENT_DIR)
    }

    /// `/etc/mooring`, which holds the generations.
    pub(crate) fn etc(&self) -> PathBuf {
        self.at(ETC_DIR)
    }

    /// The directory of generation `generation`, `/etc/mooring/gen-<N>`.
    pub(crate) fn generation(&self, generation: Generation) -> PathBuf {
        self.etc().join(generation_name(generation))
    }

    /// The transaction records, `/var/lib/mooring/txn`.
    pub(crate) fn txn_dir(&self) -> PathBuf {
        self.var_lib().join("txn")
    }

    /// The record of the transaction for `generation`.
    pub(crate) fn txn_record(&self, generation: Generation) -> PathBuf {
        self.txn_dir()
            .join(format!("gen-{}.json", generation.get()))
    }

    /// The change in flight and its phase,
    /// `/var/lib/mooring/txn/pending.json`.
    pub(crate) fn pending(&self) -> PathBuf {
        self.txn_dir().join("pending.json")
    }

    /// The transaction lock, `/run/mooring/txn.lock`.
    pub(crate) fn txn_lock(&self) -> PathBuf {
        self.at(RUN).join("txn.lock")
    }

    /// Scratch space for the validators' copies, `/run/mooring/validate`.
    pub(crate) fn validate_dir(&self) -> PathBuf {
        self.at(RUN).join("validate")
    }

    /// The engine store, `/opt/mooring/engines/store`.
    pub(crate) fn engine_store(&self) -> PathBuf {
        self.at("/opt/mooring/engines/store")
    }

    /// The fixed link Xray's `XRAY_LOCATION_ASSET` names,
    /// `/opt/mooring/engines/geodata/current`.
    pub(crate) fn geodata_link(&self) -> PathBuf {
        self.at(XRAY_ASSET_DIR)
    }

    /// `/etc/wireguard/wgexit.conf`, a link into the current generation.
    pub(crate) fn wg_conf_link(&self) -> PathBuf {
        self.at(ManagedFile::WgConf.path())
    }

    /// `/etc/nftables.conf`, a link into the current generation.
    pub(crate) fn nft_conf_link(&self) -> PathBuf {
        self.at(ManagedFile::Nftables.path())
    }

    /// The installed agents, `/usr/local/lib/mooring/agent`.
    pub(crate) fn agent_dir(&self) -> PathBuf {
        self.at(AGENT_DIR)
    }

    /// The forced command's link, `/usr/local/lib/mooring/agent/current`.
    pub(crate) fn agent_current(&self) -> PathBuf {
        self.at(AGENT_CURRENT_PATH)
    }

    /// A file of the kernel's `/proc/sys`.
    pub(crate) fn proc_sys(&self, key: &str) -> PathBuf {
        self.at("/proc/sys").join(key)
    }

    /// `net.ipv4.conf.wgexit.accept_local`.
    pub(crate) fn wgexit_accept_local(&self) -> PathBuf {
        self.proc_sys(&format!("net/ipv4/conf/{WG_INTERFACE}/accept_local"))
    }

    /// A file of the kernel's `/proc`.
    pub(crate) fn proc(&self, name: &str) -> PathBuf {
        self.at("/proc").join(name)
    }

    /// The watch's state, `/var/lib/mooring/watch` (design §11.3).
    pub(crate) fn watch_dir(&self) -> PathBuf {
        self.var_lib().join("watch")
    }

    /// The watch's view at its latest tick,
    /// `/var/lib/mooring/watch/status.json`.
    pub(crate) fn watch_status(&self) -> PathBuf {
        self.watch_dir().join("status.json")
    }

    /// The node's event journal, `/var/lib/mooring/watch/journal.jsonl`
    /// (design §15.7).
    pub(crate) fn journal(&self) -> PathBuf {
        self.watch_dir().join("journal.jsonl")
    }

    /// The accounting files, `/var/lib/mooring/usage` (design §11.5).
    pub(crate) fn usage_dir(&self) -> PathBuf {
        self.var_lib().join("usage")
    }

    /// The latest accounting poll and the usage series,
    /// `/var/lib/mooring/usage/accounting.json`.
    pub(crate) fn accounting(&self) -> PathBuf {
        self.usage_dir().join("accounting.json")
    }

    /// One month's usage, `/var/lib/mooring/usage/<YYYY-MM>.json`.
    pub(crate) fn usage_month(&self, month: UsageMonth) -> PathBuf {
        self.usage_dir().join(format!("{month}.json"))
    }

    /// One of `interface`'s kernel counters,
    /// `/sys/class/net/<interface>/statistics/<counter>`.
    pub(crate) fn net_statistic(&self, interface: &IfName, counter: &str) -> PathBuf {
        self.at("/sys/class/net")
            .join(interface.as_str())
            .join("statistics")
            .join(counter)
    }

    /// The current generation's `watch.json`.
    pub(crate) fn watch_config(&self) -> PathBuf {
        self.at(ManagedFile::WatchConfig.path())
    }

    /// `/run/reboot-required`, which an upgrade that needs a reboot
    /// creates.
    pub(crate) fn reboot_required(&self) -> PathBuf {
        self.at("/run/reboot-required")
    }

    /// journald's persistent journal, `/var/log/journal`.
    pub(crate) fn persistent_journal(&self) -> PathBuf {
        self.at("/var/log/journal")
    }

    /// The log unattended-upgrades writes when it installs packages.
    pub(crate) fn unattended_upgrades_log(&self) -> PathBuf {
        self.at("/var/log/unattended-upgrades/unattended-upgrades-dpkg.log")
    }

    /// `/etc/os-release`.
    pub(crate) fn os_release(&self) -> PathBuf {
        self.at("/etc/os-release")
    }

    /// `/etc/passwd`.
    pub(crate) fn passwd(&self) -> PathBuf {
        self.at("/etc/passwd")
    }

    /// `/etc/group`.
    pub(crate) fn group(&self) -> PathBuf {
        self.at("/etc/group")
    }

    /// Root's `authorized_keys`, which holds the bootstrap and ops lines
    /// (design §8.6).
    pub(crate) fn root_authorized_keys(&self) -> PathBuf {
        self.at("/root/.ssh/authorized_keys")
    }

    /// sshd's host keys, `/etc/ssh`.
    pub(crate) fn ssh_dir(&self) -> PathBuf {
        self.at("/etc/ssh")
    }

    /// The ed25519 host key, `/etc/ssh/ssh_host_ed25519_key` (its public
    /// half beside it, `.pub`).
    pub(crate) fn ssh_host_key(&self) -> PathBuf {
        self.ssh_dir().join("ssh_host_ed25519_key")
    }

    /// The host key `Bootstrap` made, `/var/lib/mooring/host-key.json`:
    /// once it is recorded, a second `Bootstrap` keeps the key.
    pub(crate) fn host_key_record(&self) -> PathBuf {
        self.var_lib().join("host-key.json")
    }

    /// Where a host-profile file is installed.
    pub(crate) fn host_file(&self, file: HostFile) -> PathBuf {
        self.at(file.path())
    }

    /// The running agent's own executable, `/proc/self/exe`.
    pub(crate) fn own_executable(&self) -> PathBuf {
        self.at("/proc/self/exe")
    }
}
