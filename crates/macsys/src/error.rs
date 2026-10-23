// SPDX-License-Identifier: GPL-3.0-or-later

//! The crate's typed errors (design §14). Written by hand: the crate has no
//! dependency but libc, so neither `thiserror` nor the model's `kinds!`.

use std::fmt;

/// A kernel table or terminal operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacsysError {
    /// The interface name is empty, longer than 15 bytes or holds a NUL.
    InvalidInterfaceName,
    /// No interface has that name.
    InterfaceAbsent,
    /// `sysctl` failed with this `errno`.
    Sysctl {
        /// The `errno` value.
        errno: i32,
    },
    /// The table kept growing between sizing and reading it, through every
    /// retry.
    TableChanged,
    /// The table is larger than 16 MiB.
    TableTooLarge,
    /// The kernel's routing messages break their own lengths or version.
    MalformedRoute {
        /// What is wrong.
        fault: RouteFault,
    },
    /// The interface has no IPv4 default route through a gateway.
    NoDefaultRoute,
    /// The interface has IPv4 default routes through more than one gateway.
    AmbiguousDefaultRoute,
    /// The kernel's neighbour table dump (`NET_RT_FLAGS` with `RTF_LLINFO`)
    /// was empty: 0 bytes, so no entry at all. That is all this crate
    /// states; whether the table was empty or hidden from this process is
    /// for the caller to judge. Measured on macOS 27.0.1 (26A434) on
    /// 2026-10-14 (design §15.6 rule 10): the dump was empty to a reader
    /// whose code-signing identifier is not reverse-DNS, and to a reader
    /// with an ad-hoc-signed ancestor (a copy of bash, cargo or nextest); a
    /// Developer ID-signed ancestor did not empty it. That the kernel hides
    /// the table because of how a process and its ancestors are signed, and
    /// from every such process, is an inference from those cases.
    NeighbourTableEmpty,
    /// The neighbour table has no entry for the address on the interface.
    NeighbourAbsent,
    /// The entry for the address is still being resolved (no link-layer
    /// address yet).
    NeighbourIncomplete,
    /// The entry's link-layer address is not six bytes long.
    NotEthernet {
        /// Its length in bytes.
        alen: u8,
    },
    /// The neighbour table holds different entries for the address on the
    /// interface.
    AmbiguousNeighbour,
    /// `getrlimit` or `setrlimit` for the open-files limit failed with
    /// this `errno`.
    Rlimit {
        /// The call.
        call: RlimitCall,
        /// The `errno` value.
        errno: i32,
    },
    /// A terminal attribute call failed with this `errno`.
    Terminal {
        /// The call.
        call: TerminalCall,
        /// The `errno` value.
        errno: i32,
    },
    /// The kernel's boot time (`kern.boottime`) was not one `timeval` at
    /// or after the epoch.
    BootTimeInvalid,
    /// A process call failed with this `errno`.
    Process {
        /// The call.
        call: ProcessCall,
        /// The `errno` value.
        errno: i32,
    },
}

impl fmt::Display for MacsysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInterfaceName => {
                f.write_str("the interface name is empty, longer than 15 bytes or holds a NUL")
            }
            Self::InterfaceAbsent => f.write_str("no interface has that name"),
            Self::Sysctl { errno } => write!(f, "sysctl failed with errno {errno}"),
            Self::TableChanged => {
                f.write_str("the kernel table kept growing while it was being read")
            }
            Self::TableTooLarge => f.write_str("the kernel table is larger than 16 MiB"),
            Self::MalformedRoute { fault } => write!(f, "a kernel routing message {fault}"),
            Self::NoDefaultRoute => {
                f.write_str("the interface has no IPv4 default route through a gateway")
            }
            Self::AmbiguousDefaultRoute => {
                f.write_str("the interface has IPv4 default routes through more than one gateway")
            }
            Self::NeighbourTableEmpty => {
                f.write_str("the kernel's neighbour table dump was empty (0 bytes)")
            }
            Self::NeighbourAbsent => {
                f.write_str("the neighbour table has no entry for the gateway on the interface")
            }
            Self::NeighbourIncomplete => {
                f.write_str("the gateway's neighbour entry has no link-layer address yet")
            }
            Self::NotEthernet { alen } => write!(
                f,
                "the gateway's link-layer address is {alen} bytes long, not 6"
            ),
            Self::AmbiguousNeighbour => f.write_str(
                "the neighbour table holds different entries for the gateway on the interface",
            ),
            Self::Rlimit { call, errno } => {
                write!(
                    f,
                    "{call} of the open-files limit failed with errno {errno}"
                )
            }
            Self::Terminal { call, errno } => write!(f, "{call} failed with errno {errno}"),
            Self::BootTimeInvalid => {
                f.write_str("the kernel's boot time is not one time at or after the epoch")
            }
            Self::Process { call, errno } => write!(f, "{call} failed with errno {errno}"),
        }
    }
}

impl std::error::Error for MacsysError {}

/// The kind of a [`MacsysError`], without its details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MacsysErrorKind {
    /// See [`MacsysError::InvalidInterfaceName`].
    InvalidInterfaceName,
    /// See [`MacsysError::InterfaceAbsent`].
    InterfaceAbsent,
    /// See [`MacsysError::Sysctl`].
    Sysctl,
    /// See [`MacsysError::TableChanged`].
    TableChanged,
    /// See [`MacsysError::TableTooLarge`].
    TableTooLarge,
    /// See [`MacsysError::MalformedRoute`].
    MalformedRoute,
    /// See [`MacsysError::NoDefaultRoute`].
    NoDefaultRoute,
    /// See [`MacsysError::AmbiguousDefaultRoute`].
    AmbiguousDefaultRoute,
    /// See [`MacsysError::NeighbourTableEmpty`].
    NeighbourTableEmpty,
    /// See [`MacsysError::NeighbourAbsent`].
    NeighbourAbsent,
    /// See [`MacsysError::NeighbourIncomplete`].
    NeighbourIncomplete,
    /// See [`MacsysError::NotEthernet`].
    NotEthernet,
    /// See [`MacsysError::AmbiguousNeighbour`].
    AmbiguousNeighbour,
    /// See [`MacsysError::Rlimit`].
    Rlimit,
    /// See [`MacsysError::Terminal`].
    Terminal,
    /// See [`MacsysError::BootTimeInvalid`].
    BootTimeInvalid,
    /// See [`MacsysError::Process`].
    Process,
}

impl MacsysErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::InvalidInterfaceName,
        Self::InterfaceAbsent,
        Self::Sysctl,
        Self::TableChanged,
        Self::TableTooLarge,
        Self::MalformedRoute,
        Self::NoDefaultRoute,
        Self::AmbiguousDefaultRoute,
        Self::NeighbourTableEmpty,
        Self::NeighbourAbsent,
        Self::NeighbourIncomplete,
        Self::NotEthernet,
        Self::AmbiguousNeighbour,
        Self::Rlimit,
        Self::Terminal,
        Self::BootTimeInvalid,
        Self::Process,
    ];

    /// The stable name of this kind: its variant identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidInterfaceName => "InvalidInterfaceName",
            Self::InterfaceAbsent => "InterfaceAbsent",
            Self::Sysctl => "Sysctl",
            Self::TableChanged => "TableChanged",
            Self::TableTooLarge => "TableTooLarge",
            Self::MalformedRoute => "MalformedRoute",
            Self::NoDefaultRoute => "NoDefaultRoute",
            Self::AmbiguousDefaultRoute => "AmbiguousDefaultRoute",
            Self::NeighbourTableEmpty => "NeighbourTableEmpty",
            Self::NeighbourAbsent => "NeighbourAbsent",
            Self::NeighbourIncomplete => "NeighbourIncomplete",
            Self::NotEthernet => "NotEthernet",
            Self::AmbiguousNeighbour => "AmbiguousNeighbour",
            Self::Rlimit => "Rlimit",
            Self::Terminal => "Terminal",
            Self::BootTimeInvalid => "BootTimeInvalid",
            Self::Process => "Process",
        }
    }
}

impl fmt::Display for MacsysErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl MacsysError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> MacsysErrorKind {
        match self {
            Self::InvalidInterfaceName => MacsysErrorKind::InvalidInterfaceName,
            Self::InterfaceAbsent => MacsysErrorKind::InterfaceAbsent,
            Self::Sysctl { .. } => MacsysErrorKind::Sysctl,
            Self::TableChanged => MacsysErrorKind::TableChanged,
            Self::TableTooLarge => MacsysErrorKind::TableTooLarge,
            Self::MalformedRoute { .. } => MacsysErrorKind::MalformedRoute,
            Self::NoDefaultRoute => MacsysErrorKind::NoDefaultRoute,
            Self::AmbiguousDefaultRoute => MacsysErrorKind::AmbiguousDefaultRoute,
            Self::NeighbourTableEmpty => MacsysErrorKind::NeighbourTableEmpty,
            Self::NeighbourAbsent => MacsysErrorKind::NeighbourAbsent,
            Self::NeighbourIncomplete => MacsysErrorKind::NeighbourIncomplete,
            Self::NotEthernet { .. } => MacsysErrorKind::NotEthernet,
            Self::AmbiguousNeighbour => MacsysErrorKind::AmbiguousNeighbour,
            Self::Rlimit { .. } => MacsysErrorKind::Rlimit,
            Self::Terminal { .. } => MacsysErrorKind::Terminal,
            Self::BootTimeInvalid => MacsysErrorKind::BootTimeInvalid,
            Self::Process { .. } => MacsysErrorKind::Process,
        }
    }
}

/// How a kernel routing message breaks its form
/// ([`MacsysError::MalformedRoute`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteFault {
    /// Fewer bytes than a message header.
    ShortHeader,
    /// The message's length runs past the end of the table.
    LengthOverrun,
    /// The message is not of `RTM_VERSION`.
    Version,
    /// A socket address runs past the end of its message, or a link-layer
    /// address past the end of its socket address.
    SockaddrOverrun,
    /// An interface list holds a message of a type it should not hold.
    UnexpectedType {
        /// The message's type (`ifm_type`).
        rtm_type: u8,
    },
    /// An interface's message has no `AF_LINK` socket address.
    MissingLink,
    /// An interface's message names interface index 0.
    ZeroIndex,
    /// An interface's name is empty or not UTF-8.
    InvalidName,
    /// An address message names an interface the list has not given.
    UnknownInterface,
    /// The list gives the same interface twice.
    DuplicateInterface,
    /// A netmask's ones are not contiguous.
    NonContiguousMask,
}

impl fmt::Display for RouteFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ShortHeader => "is shorter than its header",
            Self::LengthOverrun => "runs past the end of the table",
            Self::Version => "is not of the routing message version this build reads",
            Self::SockaddrOverrun => "has a socket address that runs past its end",
            Self::UnexpectedType { rtm_type } => {
                return write!(
                    f,
                    "is of type {rtm_type}, which an interface list does not hold"
                );
            }
            Self::MissingLink => "describes an interface without a link-layer socket address",
            Self::ZeroIndex => "describes an interface with index 0",
            Self::InvalidName => "names an interface with an empty or non-UTF-8 name",
            Self::UnknownInterface => "gives an address of an interface the list has not given",
            Self::DuplicateInterface => "repeats an interface the list has already given",
            Self::NonContiguousMask => "has a netmask whose ones are not contiguous",
        })
    }
}

/// The resource-limit call that failed ([`MacsysError::Rlimit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RlimitCall {
    /// `getrlimit`.
    Get,
    /// `setrlimit`.
    Set,
}

impl fmt::Display for RlimitCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "getrlimit",
            Self::Set => "setrlimit",
        })
    }
}

/// The terminal call that failed ([`MacsysError::Terminal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalCall {
    /// `tcgetattr`.
    GetAttributes,
    /// `tcsetattr`.
    SetAttributes,
}

impl fmt::Display for TerminalCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GetAttributes => "tcgetattr",
            Self::SetAttributes => "tcsetattr",
        })
    }
}

/// The process call that failed ([`MacsysError::Process`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessCall {
    /// `proc_pidpath`.
    PidPath,
    /// `kill`.
    Kill,
}

impl fmt::Display for ProcessCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PidPath => "proc_pidpath",
            Self::Kill => "kill",
        })
    }
}

/// The calling thread's `errno`, read right after a failed call.
pub(crate) fn last_errno() -> i32 {
    // SAFETY: `__error` has no preconditions; it returns the address of
    // the calling thread's `errno`.
    let location = unsafe { libc::__error() };
    // SAFETY: that address is valid, aligned and initialised for the life
    // of the thread, and nothing else writes it between the two calls.
    unsafe { location.read() }
}
