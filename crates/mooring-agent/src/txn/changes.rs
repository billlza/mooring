// SPDX-License-Identifier: GPL-3.0-or-later

//! Applying what changed between two generations (design §11.2 steps 4
//! and 5): the host profile's files, installed as the swap's last part
//! (step 4), then the ruleset, the tunnel, what those files need, and the
//! engines whose configuration, artifacts or unit changed (step 5). Each
//! tool's failure is reported through [`Step`], scrubbed of the
//! generation's secrets; the rollback to nothing runs its tools through a
//! `Step` too, with no secrets to scrub.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, BundleHeader, EngineUser, HostFile, IoOp, ManagedFile, RollbackCause,
    StderrTail, UnitName, WG_INTERFACE,
};

use super::validate;
use crate::gate;
use crate::host::{Node, Tool, run_ok};
use crate::hostfiles::{self, Applied};
use crate::paths::Paths;
use crate::store::{Scratch, errno, io_error};

/// Every value of `key` in a WireGuard configuration, in order: a hook may
/// be given more than once.
fn wg_values(conf: &str, key: &str) -> Vec<String> {
    conf.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.trim().to_owned())
        })
        .collect()
}

/// The `wgexit.conf` keys only `wg-quick` reads, which `wg syncconf` leaves
/// as they are: a change to any of them needs the tunnel restarted. The
/// hooks are among them: the abuse guard's `local` route for the users'
/// source addresses is a `PostUp` line (design §11.8), and a generation that
/// added it with `wg syncconf` alone would leave every user's bind failing
/// until the next reboot.
pub(crate) const WG_QUICK_KEYS: [&str; 7] = [
    "Address", "MTU", "Table", "PreUp", "PostUp", "PreDown", "PostDown",
];

/// Installs the host profile's files staged with the generation in `dir`
/// (the swap's last part, design §11.2 step 4) and returns those to apply,
/// as `applied` says. A generation an older agent staged has none, and
/// changes none.
pub(super) fn install_host(
    paths: &Paths,
    dir: &Path,
    applied: Applied,
) -> Result<BTreeSet<HostFile>, RollbackCause> {
    let staged = dir.join(hostfiles::HOST_DIR);
    if !staged.is_dir() {
        return Ok(BTreeSet::new());
    }
    let changed = hostfiles::install(paths, &staged).map_err(|error| RollbackCause::Swap {
        errno: errno(&error),
    })?;
    Ok(applied.files(changed))
}

/// Applies only what changed (design §11.2 step 5) from `before` to the
/// generation now current, in `dir`: the ruleset, the tunnel (a restart if
/// a key only wg-quick reads changed, else `wg syncconf`), what the host profile
/// files in `host` need, and the engines whose configuration, artifacts or
/// unit changed. No engine is restarted while the node is halted. Tool
/// output is scrubbed of the generation's secrets; if they cannot be read,
/// nothing is run.
pub(super) fn apply_changes(
    paths: &Paths,
    node: &dyn Node,
    before: Option<&BundleHeader>,
    next: &BundleHeader,
    dir: &Path,
    host: &BTreeSet<HostFile>,
) -> Result<(), RollbackCause> {
    let secrets = validate::secrets(dir).map_err(|error| RollbackCause::Apply {
        step: ApplyStep::Nftables,
        stderr_tail: StderrTail::scrubbed(error.to_string().as_bytes(), &[]),
    })?;
    let step = Step {
        node,
        secrets: &secrets,
    };
    let changed = |file: ManagedFile| {
        before.is_none_or(|before| before.files.get(file) != next.files.get(file))
    };
    if changed(ManagedFile::Nftables) {
        let file = paths.nft_conf_link().display().to_string();
        step.run(ApplyStep::Nftables, Tool::Nft, &["-f", &file])?;
    }
    if changed(ManagedFile::WgConf) {
        apply_wireguard(paths, &step, before, dir)?;
    }
    for command in hostfiles::commands(host) {
        let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
        step.run(command.step.apply_step(), command.tool, &args)?;
    }
    if gate::halted(paths)
        .map_err(|error| step.failed(ApplyStep::EngineRestart, &error))?
        .is_some()
    {
        return Ok(());
    }
    let engines_changed = before.is_none_or(|before| before.engines != next.engines);
    for (engine, file, unit) in [
        (
            EngineUser::Xray,
            ManagedFile::XrayConfig,
            HostFile::XrayUnit,
        ),
        (EngineUser::Hy2, ManagedFile::Hy2Config, HostFile::Hy2Unit),
    ] {
        if changed(file) || engines_changed || host.contains(&unit) {
            step.run(
                ApplyStep::EngineRestart,
                Tool::Systemctl,
                &["restart", UnitName::engine(engine).as_str()],
            )?;
        }
    }
    Ok(())
}

/// One apply step's tool runs, their failures scrubbed of `secrets`.
pub(super) struct Step<'a> {
    pub(super) node: &'a dyn Node,
    pub(super) secrets: &'a [Vec<u8>],
}

impl Step<'_> {
    fn tail(&self, text: &[u8]) -> StderrTail {
        let refs: Vec<&[u8]> = self.secrets.iter().map(Vec::as_slice).collect();
        StderrTail::scrubbed(text, &refs)
    }

    pub(super) fn failed(&self, step: ApplyStep, error: &AgentError) -> RollbackCause {
        RollbackCause::Apply {
            step,
            stderr_tail: self.tail(error.to_string().as_bytes()),
        }
    }

    /// Runs `tool`; its stdout, or the step's failure with its stderr.
    pub(super) fn run(
        &self,
        step: ApplyStep,
        tool: Tool,
        args: &[&str],
    ) -> Result<Vec<u8>, RollbackCause> {
        match run_ok(self.node, tool, args) {
            Ok(Ok(stdout)) => Ok(stdout),
            Ok(Err(stderr)) => Err(RollbackCause::Apply {
                step,
                stderr_tail: self.tail(&stderr),
            }),
            Err(error) => Err(self.failed(step, &error)),
        }
    }
}

/// The tunnel's step: `wg-quick@wgexit` restarted when it is new or one of
/// [`WG_QUICK_KEYS`] changed (or the old configuration cannot be read),
/// else the peers synchronised with `wg syncconf`.
fn apply_wireguard(
    paths: &Paths,
    step: &Step<'_>,
    before: Option<&BundleHeader>,
    dir: &Path,
) -> Result<(), RollbackCause> {
    let next = fs::read_to_string(dir.join(ManagedFile::WgConf.file_name()))
        .map_err(|error| step.failed(ApplyStep::WireGuard, &io_error(IoOp::ReadState, &error)))?;
    let restart = before.is_none_or(|before| {
        let old = paths
            .generation(before.config_generation)
            .join(ManagedFile::WgConf.file_name());
        fs::read_to_string(old).map_or(true, |old| {
            WG_QUICK_KEYS
                .iter()
                .any(|key| wg_values(&old, key) != wg_values(&next, key))
        })
    });
    if restart {
        return step
            .run(
                ApplyStep::WireGuard,
                Tool::Systemctl,
                &["restart", UnitName::tunnel().as_str()],
            )
            .map(drop);
    }
    let conf = paths.wg_conf_link().display().to_string();
    let stripped = step.run(ApplyStep::WireGuard, Tool::WgQuick, &["strip", &conf])?;
    // The stripped copy holds the private key; it goes whatever happens.
    let scratch = Scratch::write(paths.validate_dir().join("wgexit.stripped"), &stripped)
        .map_err(|error| step.failed(ApplyStep::WireGuard, &io_error(IoOp::WriteState, &error)))?;
    let scratch_arg = scratch.path().display().to_string();
    step.run(
        ApplyStep::WireGuard,
        Tool::Wg,
        &["syncconf", WG_INTERFACE, &scratch_arg],
    )
    .map(drop)
}
