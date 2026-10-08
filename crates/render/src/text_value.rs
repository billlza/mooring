// SPDX-License-Identifier: GPL-3.0-or-later

//! Small typed values that engines read as strings.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use mooring_model::ipv4::PublicIpv4;
use mooring_model::ports::Port;

/// Serialises a value as its `Display` text and reads it back with `FromStr`.
macro_rules! display_serde {
    ($name:ty) => {
        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                <String as ::serde::Deserialize>::deserialize(deserializer)?
                    .parse()
                    .map_err(::serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use display_serde;

/// Why a text value could not be read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TextValueError(pub(crate) &'static str);

impl fmt::Display for TextValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not {}", self.0)
    }
}

/// A public IPv4 endpoint, `<ipv4>:<port>`: the REALITY `target` and the
/// camouflage `redirect`, which therefore can only name a public address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PublicSocket {
    pub(crate) ip: PublicIpv4,
    pub(crate) port: Port,
}

impl fmt::Display for PublicSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

impl FromStr for PublicSocket {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        const WHAT: TextValueError = TextValueError("a public <ipv4>:<port>");
        let (ip, port) = text.split_once(':').ok_or(WHAT)?;
        Ok(Self {
            ip: ip.parse().map_err(|_| WHAT)?,
            port: port
                .parse::<u16>()
                .ok()
                .and_then(|port| Port::new(port).ok())
                .ok_or(WHAT)?,
        })
    }
}

display_serde!(PublicSocket);

/// A port written as a decimal string (Xray routing `port`, `common.go:247-278`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PortText(pub(crate) Port);

impl fmt::Display for PortText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for PortText {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse::<u16>()
            .ok()
            .and_then(|port| Port::new(port).ok())
            .map(Self)
            .ok_or(TextValueError("a port number"))
    }
}

display_serde!(PortText);

/// One entry of an Xray `ip` list (`common/geodata/rule_parser.go:16-48`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IpMatch {
    /// A canonical IPv4 prefix, such as a `SPECIAL_V4` class.
    Net(Ipv4Net),
    /// One IPv4 address, such as a node's.
    Host(Ipv4Addr),
    /// `::/0`: every IPv6 destination (v1 refuses IPv6 entirely).
    AllIpv6,
    /// `geoip:cn`, from the pinned `geoip.dat`.
    GeoipCn,
}

const ALL_IPV6: &str = "::/0";
const GEOIP_CN: &str = "geoip:cn";

impl fmt::Display for IpMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Net(net) => net.fmt(f),
            Self::Host(addr) => addr.fmt(f),
            Self::AllIpv6 => f.write_str(ALL_IPV6),
            Self::GeoipCn => f.write_str(GEOIP_CN),
        }
    }
}

impl FromStr for IpMatch {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        const WHAT: TextValueError =
            TextValueError("an IPv4 address, IPv4 prefix, ::/0 or geoip:cn");
        match text {
            ALL_IPV6 => Ok(Self::AllIpv6),
            GEOIP_CN => Ok(Self::GeoipCn),
            _ if text.contains('/') => {
                let net: Ipv4Net = text.parse().map_err(|_| WHAT)?;
                (net.network() == net.addr() && net.to_string() == text)
                    .then_some(Self::Net(net))
                    .ok_or(WHAT)
            }
            _ => text.parse().map(Self::Host).map_err(|_| WHAT),
        }
    }
}

display_serde!(IpMatch);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_values_round_trip_and_reject_other_spellings() {
        for text in ["1.2.3.0/24", "1.2.3.4", "::/0", "geoip:cn"] {
            let value: IpMatch = text.parse().unwrap();
            assert_eq!(value.to_string(), text);
        }
        for bad in ["1.2.3.4/24", "geoip:us", "::1", "a"] {
            assert!(bad.parse::<IpMatch>().is_err(), "{bad}");
        }
        let socket: PublicSocket = "45.67.89.10:443".parse().unwrap();
        assert_eq!(socket.to_string(), "45.67.89.10:443");
        for bad in [
            "10.0.0.1:443",
            "45.67.89.10:0",
            "45.67.89.10",
            "45.67.89.10:x",
        ] {
            assert!(bad.parse::<PublicSocket>().is_err(), "{bad}");
        }
        assert_eq!("27900".parse::<PortText>().unwrap().0.get(), 27900);
        assert!("0".parse::<PortText>().is_err());
    }
}
