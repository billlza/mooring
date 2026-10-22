// SPDX-License-Identifier: GPL-3.0-or-later

//! `serve-ssh --role <role>`, the forced command (design §11.1): one request
//! on stdin, checked against the role before anything is done, one reply on
//! stdout. A request this build does not serve yet is answered
//! `NotServedYet`, never with a guess.

use std::io::{BufRead, Write};

use mooring_agent_proto::{
    AgentError, LineRequest, Reply, Request, RequestKind, Response, Role, StoredMacReport,
    WriteError, expect_end_of_input, read_request, write_reply,
};

use crate::host::Node;
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::{blobs, gate, hello, txn};

/// Who sent the request: the role its key's forced command names, and
/// `SSH_CONNECTION` as sshd set it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Session<'a> {
    /// The role.
    pub(crate) role: Role,
    /// `SSH_CONNECTION`, if set.
    pub(crate) ssh_connection: Option<&'a str>,
}

/// Reads one request from `input`, answers it on `output`.
pub(crate) fn serve(
    paths: &Paths,
    node: &dyn Node,
    session: Session<'_>,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<(), WriteError> {
    let reply = answer(paths, node, session, input);
    write_reply(output, &reply)
}

/// The reply to the request on `input`.
pub(crate) fn answer(
    paths: &Paths,
    node: &dyn Node,
    session: Session<'_>,
    input: &mut impl BufRead,
) -> Reply {
    let request = read_request(input).map_err(|error| error.to_agent_error())?;
    request.authorize(session.role)?;
    match request {
        Request::PutBlob { sha256, len } => {
            blobs::put(paths, sha256, len, input)?;
            Ok(Response::BlobStored { sha256 })
        }
        Request::Line(line) => {
            expect_end_of_input(input).map_err(|error| error.to_agent_error())?;
            line_reply(paths, node, session, line)
        }
    }
}

fn line_reply(paths: &Paths, node: &dyn Node, session: Session<'_>, line: LineRequest) -> Reply {
    match line {
        LineRequest::Hello => Ok(Response::Hello(Box::new(hello::hello(
            paths,
            node,
            session.ssh_connection,
        )?))),
        LineRequest::HaveBlobs { blobs } => Ok(Response::Blobs {
            present: blobs::present(paths, &blobs)?,
        }),
        LineRequest::GateSet { reason } => {
            let holds = match session.role {
                Role::Viewer => gate::set_by_viewer(paths, node)?,
                Role::Ops => gate::set_by_ops(paths, node, reason)?,
                // `authorize` has refused it already; kept explicit so the
                // bootstrap key can never reach a gate handler.
                Role::Bootstrap => {
                    return Err(AgentError::RoleNotPermitted {
                        role: Role::Bootstrap,
                        request: RequestKind::GateSet,
                    });
                }
            };
            Ok(Response::GateClosed { holds })
        }
        LineRequest::ClearHold { hold } => Ok(Response::HoldCleared {
            holds: gate::clear(paths, hold)?,
        }),
        LineRequest::Shutdown { reason } => {
            Ok(Response::Halted(gate::shutdown(paths, node, reason)?))
        }
        LineRequest::PutMacReport(report) => {
            let at = report.parts().at;
            let stored = StoredMacReport {
                received_at: node.now(),
                report: *report,
            };
            write_json(&paths.mac_report(), &stored, 0o640)?;
            Ok(Response::MacReportStored { at })
        }
        LineRequest::MacReport => read_json::<StoredMacReport>(&paths.mac_report())?
            .map(|stored| Response::MacReport(Box::new(stored)))
            .ok_or(AgentError::MacReportMissing),
        LineRequest::Apply(header) => Ok(match txn::apply(paths, node, *header)? {
            txn::Launched::Launched(generation) => Response::TxnLaunched { generation },
            txn::Launched::Unchanged(generation) => Response::Unchanged { generation },
        }),
        LineRequest::TxnStatus { generation } => Ok(Response::TxnStatus {
            generation,
            state: txn::status(paths, generation)?,
        }),
        LineRequest::Confirm { generation } => Ok(Response::Confirmed {
            generation: txn::confirm(paths, node, generation)?,
        }),
        LineRequest::Rollback => Ok(Response::Reverted {
            generation: txn::revert_pending(paths, node, txn::Why::Requested)?,
        }),
        LineRequest::ActivateAgent { sha } => Ok(Response::AwaitingConfirm {
            generation: txn::activate::activate(paths, node, sha)?,
        }),
        LineRequest::Resume { config_generation } => Ok(Response::Resumed {
            generation: txn::resume::resume(paths, node, config_generation)?,
        }),
        LineRequest::Bootstrap { .. }
        | LineRequest::RevokeBootstrap
        | LineRequest::Status
        | LineRequest::Usage { .. }
        | LineRequest::UsageSeries(_)
        | LineRequest::Events { .. }
        | LineRequest::TargetCheck { .. } => Err(AgentError::NotServedYet {
            request: line.kind(),
        }),
    }
}
