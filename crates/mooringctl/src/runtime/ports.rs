// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit machine's ports on the Mac (design §10.1, §10.2): the
//! `mooring-exit` config rendered from the Keychain's WireGuard keys (read
//! once per configuration generation), the engine checked against its pin
//! before every check and start, the direct probe, the latch file, and the
//! node calls over the operations key's sessions through the M7.
//!
//! An engine an earlier daemon left is stopped at start
//! ([`stop_stale_engine`]) only when its pid file names a process whose
//! executable is this engine. Under launchd the engine dies with the
//! daemon anyway (its process group is ended); the pid file covers a
//! daemon run by hand and killed.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use mooring_agent_proto::{ClearableHold, GateReason, LineRequest, Response, ShutdownReason};
use mooring_daemon_core::exit::{
    CallFault, ExitPorts, InChainProbe, InChainTarget, NodeCall, RenderOutcome, Rendered,
    RenderedProber, StartFault,
};
use mooring_daemon_core::status::{ProbeStage, ProcessEnd};
use mooring_model::iface::{BsdName, ResolvedInterface, ResolvedInterfaces};
use mooring_model::ports::ListenerIdx;
use mooring_model::secret::{SecretRef, SecretSnapshot};
use mooring_model::verdict::LatchRecord;
use mooring_model::{ConfigGeneration, Deployment, NodeAddress, NodeId};
use mooring_render::{ExitConfig, ProberConfig, RenderErrorKind};
use mooring_store::{SecretStoreError, SnapshotReadError, clear_latch, read_snapshot, write_latch};

use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::node::engines::{Pins, read_pinned};
use crate::node::session::{deployed_node, ops_session};
use crate::runtime::engine::{Engine, EngineError, Running};
use crate::runtime::probe::in_chain;

/// `errSecInteractionNotAllowed`: the Keychain would have to ask.
pub(crate) const INTERACTION_NOT_ALLOWED: i32 = -25_308;

/// The exit engine's path in the engine directory, as its pin names it.
pub(crate) const EXIT_ENGINE: &str = "darwin-arm64/mooring-exit";

/// The prober's path in the engine directory, as its pin names it.
pub(crate) const PROBE_ENGINE: &str = "darwin-arm64/mooring-probe";

/// The exit engine's pid file, in the run directory.
pub(crate) const ENGINE_PID_FILE: &str = "engine-exit.pid";

/// The prober's pid file, in the run directory.
pub(crate) const PROBER_PID_FILE: &str = "engine-probe.pid";

/// The ports, for one daemon.
pub(crate) struct DaemonPorts<'e, 'a> {
    env: &'e Env<'a>,
    run_dir: PathBuf,
    engines: PathBuf,
    pins: Pins<'a>,
    running: Option<Running>,
    prober: Option<Running>,
    secrets: Option<(ConfigGeneration, SecretSnapshot)>,
    egress: Option<BsdName>,
    notes: Vec<String>,
}

impl std::fmt::Debug for DaemonPorts<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonPorts")
            .field("run_dir", &self.run_dir)
            .field("engines", &self.engines)
            .field("running", &self.running)
            .field("prober", &self.prober)
            .field("egress", &self.egress)
            .finish_non_exhaustive()
    }
}

impl<'e, 'a> DaemonPorts<'e, 'a> {
    /// The ports of the daemon whose run directory is `run_dir`, running
    /// the engine in `engines` (the hosted build's directory, checked
    /// against `pins`).
    pub(crate) fn new(env: &'e Env<'a>, run_dir: PathBuf, engines: PathBuf) -> Self {
        Self {
            env,
            run_dir,
            engines,
            pins: env.mac_pins,
            running: None,
            prober: None,
            secrets: None,
            egress: None,
            notes: Vec::new(),
        }
    }

    /// The interface node calls dial through this tick: the egress, which
    /// faces the M7.
    pub(crate) fn set_egress(&mut self, egress: Option<BsdName>) {
        self.egress = egress;
    }

    /// What happened that the daemon should log, since the last call.
    pub(crate) fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    /// The engine binary at `path`, checked against its pin; a note says
    /// why one is refused.
    fn checked_engine(&mut self, path: &str) -> Result<Engine, StartFault> {
        match read_pinned(&self.engines, self.pins, path) {
            Ok(_) => Ok(Engine::new(&self.engines.join(path))),
            Err(_) => {
                self.notes.push(format!(
                    "{} is missing or does not match its pin",
                    self.engines.join(path).display()
                ));
                Err(StartFault::Spawn)
            }
        }
    }

    /// The secrets the two engines' configs hold: each applied node's
    /// WireGuard key, and the probe identity's credentials and the first
    /// listener's obfuscation password on it. They are read once per
    /// generation; `None` when the Keychain would have to ask.
    fn secrets(&mut self, deployment: &Deployment) -> Result<Option<&SecretSnapshot>, LocalError> {
        let generation = deployment.config_generation();
        if self
            .secrets
            .as_ref()
            .is_some_and(|(held, _)| *held == generation)
        {
            return Ok(self.secrets.as_ref().map(|(_, secrets)| secrets));
        }
        let refs: BTreeSet<SecretRef> = deployment
            .nodes()
            .values()
            .filter(|node| node.lifecycle.applied().is_some())
            .flat_map(|node| {
                [
                    SecretRef::NodeWgMacPrivate(node.id.clone()),
                    SecretRef::ProbeVlessUuid(node.id.clone()),
                    SecretRef::ProbeHy2Password(node.id.clone()),
                    SecretRef::NodeHy2Obfs(node.id.clone(), ListenerIdx::FIRST),
                ]
            })
            .collect();
        match read_snapshot(&*self.env.secrets, &refs) {
            Ok(snapshot) => {
                self.secrets = Some((generation, snapshot));
                Ok(self.secrets.as_ref().map(|(_, secrets)| secrets))
            }
            Err(SnapshotReadError::Store(SecretStoreError::Keychain { status, .. }))
                if status == INTERACTION_NOT_ALLOWED =>
            {
                Ok(None)
            }
            Err(error) => Err(LocalError::ExitSecrets(Box::new(error))),
        }
    }

    fn write_pid(&self, file: &str, pid: u32) -> Result<(), LocalError> {
        let path = self.run_dir.join(file);
        let failed = |source| LocalError::EnginePidFile {
            path: path.clone(),
            source,
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(failed)?;
        io::Write::write_all(&mut file, format!("{pid}\n").as_bytes()).map_err(failed)
    }

    fn remove_pid(&self, file: &str) -> Result<(), LocalError> {
        let path = self.run_dir.join(file);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LocalError::EnginePidFile { path, source }),
        }
    }
}

/// A failure to wait for or stop an engine.
fn wait_error(error: EngineError) -> LocalError {
    match error {
        EngineError::Wait(source) => LocalError::EngineWait(source),
        other => LocalError::EngineWait(io::Error::other(other.to_string())),
    }
}

/// How an engine's process ended: `wait` reports only processes that
/// exited or were signalled.
fn end_of(status: ExitStatus) -> Result<ProcessEnd, LocalError> {
    match (status.code(), status.signal()) {
        (Some(code), _) => Ok(ProcessEnd::Exited { code }),
        (None, Some(signal)) => Ok(ProcessEnd::Signalled { signal }),
        (None, None) => Err(LocalError::EngineWait(io::Error::other(format!(
            "the engine's end, {status}, is neither an exit nor a signal"
        )))),
    }
}

impl ExitPorts for DaemonPorts<'_, '_> {
    type Config = ExitConfig;
    type ProberConfig = ProberConfig;
    type Error = CommandError;

    fn render(
        &mut self,
        deployment: &Deployment,
        interfaces: &ResolvedInterfaces,
    ) -> Result<Result<Rendered<ExitConfig>, RenderOutcome>, CommandError> {
        let Some(secrets) = self.secrets(deployment)? else {
            return Ok(Err(RenderOutcome::SecretsUnavailable));
        };
        match mooring_render::mac::exit(deployment, interfaces, secrets) {
            Ok(config) => Ok(Ok(Rendered {
                digest: config.digest(),
                config,
            })),
            Err(error) if error.kind() == RenderErrorKind::NoAppliedNodes => {
                Ok(Err(RenderOutcome::NoAppliedNode))
            }
            Err(error) => Err(LocalError::ExitRender(Box::new(error)).into()),
        }
    }

    fn check(&mut self, config: &ExitConfig) -> Result<Result<(), StartFault>, CommandError> {
        let engine = match self.checked_engine(EXIT_ENGINE) {
            Ok(engine) => engine,
            Err(fault) => return Ok(Err(fault)),
        };
        match engine.check(config.file().expose_bytes()) {
            Ok(()) => Ok(Ok(())),
            Err(EngineError::Spawn { .. }) => Ok(Err(StartFault::Spawn)),
            Err(EngineError::Rejected { code, stderr }) => {
                self.notes.push(format!(
                    "mooring-exit refused its config (exit status {}): {stderr}",
                    code.map_or_else(|| "none".to_owned(), |code| code.to_string())
                ));
                Ok(Err(StartFault::Rejected))
            }
            Err(EngineError::CheckTimeout) => Ok(Err(StartFault::CheckTimedOut)),
            Err(EngineError::Config(_)) => Ok(Err(StartFault::Rejected)),
            Err(EngineError::Wait(source)) => Err(LocalError::EngineWait(source).into()),
        }
    }

    fn start(&mut self, config: &ExitConfig) -> Result<Result<u32, StartFault>, CommandError> {
        let engine = match self.checked_engine(EXIT_ENGINE) {
            Ok(engine) => engine,
            Err(fault) => return Ok(Err(fault)),
        };
        match engine.start(config.file().expose_bytes()) {
            Ok(running) => {
                let pid = running.pid();
                self.running = Some(running);
                self.write_pid(ENGINE_PID_FILE, pid)?;
                Ok(Ok(pid))
            }
            Err(EngineError::Spawn { .. }) => Ok(Err(StartFault::Spawn)),
            Err(EngineError::Config(_) | EngineError::Rejected { .. }) => {
                Ok(Err(StartFault::Rejected))
            }
            Err(EngineError::CheckTimeout) => Ok(Err(StartFault::CheckTimedOut)),
            Err(EngineError::Wait(source)) => Err(LocalError::EngineWait(source).into()),
        }
    }

    fn exited(&mut self) -> Result<Option<ProcessEnd>, CommandError> {
        let Some(running) = self.running.as_mut() else {
            return Ok(None);
        };
        let Some(status) = running.exited().map_err(wait_error)? else {
            return Ok(None);
        };
        self.running = None;
        self.remove_pid(ENGINE_PID_FILE)?;
        Ok(Some(end_of(status)?))
    }

    fn stop(&mut self) -> Result<ProcessEnd, CommandError> {
        let Some(running) = self.running.take() else {
            return Err(LocalError::EngineWait(io::Error::other("no engine runs")).into());
        };
        let status = running.stop().map_err(wait_error)?;
        self.remove_pid(ENGINE_PID_FILE)?;
        Ok(end_of(status)?)
    }

    fn probe(
        &mut self,
        via: &ResolvedInterface,
        reflector: SocketAddrV4,
    ) -> Result<Ipv4Addr, ProbeStage> {
        (self.env.probe)(via.index, reflector).map_err(|failure| failure.stage)
    }

    fn persist_latch(&mut self, latch: Option<&LatchRecord>) -> Result<(), CommandError> {
        match latch {
            Some(latch) => write_latch(&self.run_dir, latch),
            None => clear_latch(&self.run_dir),
        }
        .map_err(|error| LocalError::Latch(Box::new(error)).into())
    }

    fn call(&mut self, node: &NodeId, call: &NodeCall) -> Result<(), CallFault> {
        let request = match call {
            NodeCall::CloseGate(_) => LineRequest::GateSet {
                reason: GateReason::EgressViolation,
            },
            NodeCall::Shutdown(_) => LineRequest::Shutdown {
                reason: ShutdownReason::EgressIsNodeAddress,
            },
            NodeCall::ClearHold => LineRequest::ClearHold {
                hold: ClearableHold::EgressViolation,
            },
        };
        let Some(interface) = self.egress.clone() else {
            self.notes
                .push(format!("{node}: not asked: the egress does not resolve"));
            return Err(CallFault::Unreachable);
        };
        let outcome = (|| -> Result<Response, CommandError> {
            let state = mooring_store::Store::new(crate::app::support_dir(self.env)?)
                .load()
                .map_err(|error| LocalError::StateRead(Box::new(error)))?;
            let node = deployed_node(state.deployment.nodes(), node)?;
            let mut session = ops_session(self.env, node, &interface)?;
            Ok(session.request(&request)?)
        })();
        let expected = matches!(
            (call, &outcome),
            (NodeCall::CloseGate(_), Ok(Response::GateClosed { .. }))
                | (NodeCall::Shutdown(_), Ok(Response::Halted(_)))
                | (NodeCall::ClearHold, Ok(Response::HoldCleared { .. }))
        );
        if expected {
            self.notes
                .push(format!("{node}: {:?} done", request.kind()));
            return Ok(());
        }
        match outcome {
            Err(CommandError::Local(LocalError::Node(NodeError::Agent(error)))) => {
                self.notes.push(format!(
                    "{node}: the agent refused {:?}: {error}",
                    request.kind()
                ));
                Err(CallFault::Refused)
            }
            Ok(response) => {
                self.notes.push(format!(
                    "{node}: the agent answered {:?} with {:?}",
                    request.kind(),
                    response.kind()
                ));
                Err(CallFault::Refused)
            }
            Err(error) => {
                self.notes.push(format!(
                    "{node}: {:?} not delivered: {}",
                    request.kind(),
                    crate::daemon::chain(&error)
                ));
                Err(CallFault::Unreachable)
            }
        }
    }

    fn render_prober(
        &mut self,
        deployment: &Deployment,
        interfaces: &ResolvedInterfaces,
    ) -> Result<Result<RenderedProber<ProberConfig>, RenderOutcome>, CommandError> {
        let Some(secrets) = self.secrets(deployment)? else {
            return Ok(Err(RenderOutcome::SecretsUnavailable));
        };
        let config = match mooring_render::mac::prober(deployment, interfaces, secrets) {
            Ok(config) => config,
            Err(error) if error.kind() == RenderErrorKind::NoAppliedNodes => {
                return Ok(Err(RenderOutcome::NoAppliedNode));
            }
            Err(error) => return Err(LocalError::ExitRender(Box::new(error)).into()),
        };
        let mut targets = Vec::new();
        for probe in config.probes() {
            let node = deployment.node(&probe.node).map_err(LocalError::ExitSite)?;
            let site = node
                .lifecycle
                .site()
                .ok_or_else(|| LocalError::ProberTarget {
                    node: probe.node.clone(),
                })?;
            let NodeAddress::Public(address) = site.address;
            targets.push(InChainTarget {
                node: probe.node.clone(),
                protocol: probe.protocol,
                port: probe.port.get(),
                reflector: SocketAddrV4::new(address.get(), node.ports.reflector().get()),
            });
        }
        Ok(Ok(RenderedProber {
            digest: config.digest(),
            config,
            targets,
        }))
    }

    fn start_prober(
        &mut self,
        config: &ProberConfig,
    ) -> Result<Result<u32, StartFault>, CommandError> {
        let engine = match self.checked_engine(PROBE_ENGINE) {
            Ok(engine) => engine,
            Err(fault) => return Ok(Err(fault)),
        };
        let bytes = config.file().expose_bytes();
        let checked = match engine.check(bytes) {
            Ok(()) => Ok(()),
            Err(EngineError::Rejected { code, stderr }) => {
                self.notes.push(format!(
                    "mooring-probe refused its config (exit status {}): {stderr}",
                    code.map_or_else(|| "none".to_owned(), |code| code.to_string())
                ));
                Err(StartFault::Rejected)
            }
            Err(EngineError::Spawn { .. }) => Err(StartFault::Spawn),
            Err(EngineError::CheckTimeout) => Err(StartFault::CheckTimedOut),
            Err(EngineError::Config(_)) => Err(StartFault::Rejected),
            Err(EngineError::Wait(source)) => return Err(LocalError::EngineWait(source).into()),
        };
        if let Err(fault) = checked {
            return Ok(Err(fault));
        }
        match engine.start(bytes) {
            Ok(running) => {
                let pid = running.pid();
                self.prober = Some(running);
                self.write_pid(PROBER_PID_FILE, pid)?;
                Ok(Ok(pid))
            }
            Err(EngineError::Spawn { .. }) => Ok(Err(StartFault::Spawn)),
            Err(EngineError::Config(_) | EngineError::Rejected { .. }) => {
                Ok(Err(StartFault::Rejected))
            }
            Err(EngineError::CheckTimeout) => Ok(Err(StartFault::CheckTimedOut)),
            Err(EngineError::Wait(source)) => Err(LocalError::EngineWait(source).into()),
        }
    }

    fn prober_exited(&mut self) -> Result<Option<ProcessEnd>, CommandError> {
        let Some(running) = self.prober.as_mut() else {
            return Ok(None);
        };
        let Some(status) = running.exited().map_err(wait_error)? else {
            return Ok(None);
        };
        self.prober = None;
        self.remove_pid(PROBER_PID_FILE)?;
        Ok(Some(end_of(status)?))
    }

    fn stop_prober(&mut self) -> Result<ProcessEnd, CommandError> {
        let Some(running) = self.prober.take() else {
            return Err(LocalError::EngineWait(io::Error::other("no prober runs")).into());
        };
        let status = running.stop().map_err(wait_error)?;
        self.remove_pid(PROBER_PID_FILE)?;
        Ok(end_of(status)?)
    }

    fn probe_in_chain(&mut self, port: u16) -> Result<InChainProbe, ProbeStage> {
        in_chain(port)
            .map(|(ip, latency)| InChainProbe { ip, latency })
            .map_err(|failure| failure.stage)
    }
}

/// Stops the engine an earlier daemon left, if its pid file (`pid_file` in
/// the run directory) names a process whose executable is `engine`
/// (compared as the kernel names it, with links resolved; an engine file
/// that is gone identifies nothing); the pid file goes either way.
pub(crate) fn stop_stale_engine(
    run_dir: &Path,
    pid_file: &str,
    engine: &Path,
) -> Result<Option<u32>, LocalError> {
    let path = run_dir.join(pid_file);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(LocalError::EnginePidFile { path, source }),
    };
    let engine = fs::canonicalize(engine).ok();
    let stopped = match (text.trim().parse::<u32>(), engine) {
        (Ok(pid), Some(engine)) => {
            let running = mooring_macsys::process_path(pid)
                .map_err(|source| LocalError::StaleEngine { pid, source })?;
            if running.as_deref() == Some(engine.as_path()) {
                mooring_macsys::kill_process(pid)
                    .map_err(|source| LocalError::StaleEngine { pid, source })?;
                Some(pid)
            } else {
                None
            }
        }
        // Not a pid this daemon wrote, or no engine to compare with:
        // nothing is stopped.
        (Err(_), _) | (_, None) => None,
    };
    match fs::remove_file(&path) {
        Ok(()) => Ok(stopped),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(stopped),
        Err(source) => Err(LocalError::EnginePidFile { path, source }),
    }
}
