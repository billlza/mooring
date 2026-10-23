// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's power source (design §10.3), read with `/usr/bin/pmset -g ps`
//! until M7's power helper (`mooring-power`) reports it; this module goes
//! with that helper. The command's first line names the source macOS draws
//! from. A UPS counts as battery: the mains is off.

use std::process::Command;

use mooring_daemon_core::status::PowerSource;

use crate::error::LocalError;

/// The command.
pub(crate) const PMSET: &str = "/usr/bin/pmset";

/// The source macOS draws from now.
pub(crate) fn power_source() -> Result<PowerSource, LocalError> {
    let output = Command::new(PMSET)
        .args(["-g", "ps"])
        .output()
        .map_err(LocalError::Power)?;
    if !output.status.success() {
        return Err(LocalError::Power(std::io::Error::other(format!(
            "{PMSET} -g ps exited with {}",
            output.status
        ))));
    }
    parse(&output.stdout)
}

/// The source the first line of `pmset -g ps` names.
pub(crate) fn parse(stdout: &[u8]) -> Result<PowerSource, LocalError> {
    let first = stdout.split(|&byte| byte == b'\n').next().unwrap_or(&[]);
    match first {
        b"Now drawing from 'AC Power'" => Ok(PowerSource::Ac),
        b"Now drawing from 'Battery Power'" | b"Now drawing from 'UPS Power'" => {
            Ok(PowerSource::Battery)
        }
        _ => Err(LocalError::PowerUnreadable),
    }
}
