// SPDX-License-Identifier: GPL-3.0-or-later

//! The fixed destination port the renderers deny besides the model's
//! `SYSTEM_PORTS`, which they use by name.

/// The SMTP port, denied at both layers when `deny_smtp25` is set.
pub(crate) const SMTP_PORT: u16 = 25;
