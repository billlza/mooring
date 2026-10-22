// SPDX-License-Identifier: GPL-3.0-or-later

//! The error taxonomy: every error has its own kind, every kind is listed
//! once in `ALL` under its name, and the messages say what failed.

use std::collections::BTreeSet;

use crate::error::{MacsysError, MacsysErrorKind, RlimitCall, RouteFault, TerminalCall};

#[test]
fn every_macsys_error_has_its_kind() {
    let cases = [
        (
            MacsysError::InvalidInterfaceName,
            MacsysErrorKind::InvalidInterfaceName,
            "the interface name is empty, longer than 15 bytes or holds a NUL",
        ),
        (
            MacsysError::InterfaceAbsent,
            MacsysErrorKind::InterfaceAbsent,
            "no interface has that name",
        ),
        (
            MacsysError::Sysctl { errno: 1 },
            MacsysErrorKind::Sysctl,
            "sysctl failed with errno 1",
        ),
        (
            MacsysError::TableChanged,
            MacsysErrorKind::TableChanged,
            "the kernel table kept growing while it was being read",
        ),
        (
            MacsysError::TableTooLarge,
            MacsysErrorKind::TableTooLarge,
            "the kernel table is larger than 16 MiB",
        ),
        (
            MacsysError::MalformedRoute {
                fault: RouteFault::Version,
            },
            MacsysErrorKind::MalformedRoute,
            "a kernel routing message is not of the routing message version this build reads",
        ),
        (
            MacsysError::NoDefaultRoute,
            MacsysErrorKind::NoDefaultRoute,
            "the interface has no IPv4 default route through a gateway",
        ),
        (
            MacsysError::AmbiguousDefaultRoute,
            MacsysErrorKind::AmbiguousDefaultRoute,
            "the interface has IPv4 default routes through more than one gateway",
        ),
        (
            MacsysError::NeighbourTableEmpty,
            MacsysErrorKind::NeighbourTableEmpty,
            "the kernel's neighbour table dump was empty (0 bytes)",
        ),
        (
            MacsysError::NeighbourAbsent,
            MacsysErrorKind::NeighbourAbsent,
            "the neighbour table has no entry for the gateway on the interface",
        ),
        (
            MacsysError::NeighbourIncomplete,
            MacsysErrorKind::NeighbourIncomplete,
            "the gateway's neighbour entry has no link-layer address yet",
        ),
        (
            MacsysError::NotEthernet { alen: 8 },
            MacsysErrorKind::NotEthernet,
            "the gateway's link-layer address is 8 bytes long, not 6",
        ),
        (
            MacsysError::AmbiguousNeighbour,
            MacsysErrorKind::AmbiguousNeighbour,
            "the neighbour table holds different entries for the gateway on the interface",
        ),
        (
            MacsysError::Rlimit {
                call: RlimitCall::Set,
                errno: 22,
            },
            MacsysErrorKind::Rlimit,
            "setrlimit of the open-files limit failed with errno 22",
        ),
        (
            MacsysError::Terminal {
                call: TerminalCall::SetAttributes,
                errno: 25,
            },
            MacsysErrorKind::Terminal,
            "tcsetattr failed with errno 25",
        ),
    ];
    let kinds: BTreeSet<MacsysErrorKind> = cases.iter().map(|(_, kind, _)| *kind).collect();
    assert_eq!(kinds.len(), cases.len(), "two errors share a kind");
    assert_eq!(
        kinds,
        MacsysErrorKind::ALL
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(MacsysErrorKind::ALL.len(), cases.len());
    for (error, kind, message) in cases {
        assert_eq!(error.kind(), kind, "{error:?}");
        assert_eq!(error.to_string(), message);
        assert_eq!(kind.to_string(), kind.name());
        assert_eq!(format!("{kind:?}"), kind.name());
    }
}

#[test]
fn route_faults_and_calls_are_named() {
    for (fault, text) in [
        (RouteFault::ShortHeader, "is shorter than its header"),
        (RouteFault::LengthOverrun, "runs past the end of the table"),
        (
            RouteFault::Version,
            "is not of the routing message version this build reads",
        ),
        (
            RouteFault::SockaddrOverrun,
            "has a socket address that runs past its end",
        ),
        (
            RouteFault::UnexpectedType { rtm_type: 1 },
            "is of type 1, which an interface list does not hold",
        ),
        (
            RouteFault::MissingLink,
            "describes an interface without a link-layer socket address",
        ),
        (RouteFault::ZeroIndex, "describes an interface with index 0"),
        (
            RouteFault::InvalidName,
            "names an interface with an empty or non-UTF-8 name",
        ),
        (
            RouteFault::UnknownInterface,
            "gives an address of an interface the list has not given",
        ),
        (
            RouteFault::DuplicateInterface,
            "repeats an interface the list has already given",
        ),
        (
            RouteFault::NonContiguousMask,
            "has a netmask whose ones are not contiguous",
        ),
    ] {
        assert_eq!(fault.to_string(), text);
    }
    assert_eq!(RlimitCall::Get.to_string(), "getrlimit");
    assert_eq!(RlimitCall::Set.to_string(), "setrlimit");
    assert_eq!(TerminalCall::GetAttributes.to_string(), "tcgetattr");
    assert_eq!(TerminalCall::SetAttributes.to_string(), "tcsetattr");
}
