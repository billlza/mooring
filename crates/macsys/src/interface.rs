// SPDX-License-Identifier: GPL-3.0-or-later

//! Interface names to indices (`if_nametoindex`).

use std::ffi::CString;
use std::num::NonZeroU32;

use crate::error::MacsysError;

/// The index of the interface named `name` (for example `en9`).
///
/// A name that is empty, longer than `IFNAMSIZ - 1` (15) bytes or holds a
/// NUL is `InvalidInterfaceName`; a name no interface has is
/// `InterfaceAbsent` (`if_nametoindex` returns 0).
pub fn interface_index(name: &str) -> Result<NonZeroU32, MacsysError> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
        return Err(MacsysError::InvalidInterfaceName);
    }
    let name = CString::new(name).map_err(|_| MacsysError::InvalidInterfaceName)?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call,
    // which only reads it.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    NonZeroU32::new(index).ok_or(MacsysError::InterfaceAbsent)
}
