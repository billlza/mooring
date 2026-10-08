// SPDX-License-Identifier: GPL-3.0-or-later

//! `watch.json`: the per-generation settings of `mooring-watch`, in the
//! agent protocol's own closed type ([`WatchConfig`]).

use mooring_agent_proto::{TargetHost, WatchConfig, WatchTarget};
use mooring_model::node::Node;
use mooring_model::target::TargetSpec;

use crate::error::{RenderError, WireField};

/// Builds `watch.json` for `node` with its REALITY `target`.
pub(crate) fn config(node: &Node, target: &TargetSpec) -> Result<WatchConfig, RenderError> {
    let keepalive_secs = node.wg.keepalive.non_zero_seconds();
    let host = TargetHost::new(target.host().as_str()).map_err(|_| RenderError::WireValue {
        field: WireField::TargetHost(node.id.clone()),
    })?;
    Ok(WatchConfig {
        keepalive_secs,
        target: WatchTarget {
            host,
            ipv4: target.ipv4().get(),
        },
    })
}
