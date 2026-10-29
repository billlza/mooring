// SPDX-License-Identifier: GPL-3.0-or-later

//! configd's view of the IPv4 services (the SystemConfiguration dynamic
//! store, what `scutil` reads): for each service its interface, its router,
//! the router's link-layer address as configd resolved it when the lease
//! was taken (`ARPResolvedHardwareAddress`, kept for the service's lifetime,
//! where the kernel's own ARP entry ages out after
//! `net.link.ether.inet.max_age`, 1200 s, when nothing is sent over the
//! interface), and the DNS domain the network publishes. The own-network
//! declaration and the daemon's match both read this (design §10.2, P0-2),
//! so they cannot disagree.
//!
//! Three SystemConfiguration calls are made, each in its own unsafe block;
//! every object they return is wrapped by `core-foundation`, which owns and
//! releases it. Nothing here shells out.

use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::ptr;

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFAllocatorRef, CFRelease, CFType, TCFType, kCFAllocatorDefault};
use core_foundation::dictionary::CFDictionary;
use core_foundation::propertylist::CFPropertyListRef;
use core_foundation::string::{CFString, CFStringRef};

use crate::error::{ConfigdFault, MacsysError};

/// The pattern of every IPv4 service's key.
const IPV4_SERVICE_KEYS: &str = "State:/Network/Service/[^/]+/IPv4";

/// The suffix the service's DNS key replaces the IPv4 key's with.
const IPV4_SUFFIX: &str = "/IPv4";

/// One IPv4 service configd publishes (`State:/Network/Service/<id>/IPv4`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Service {
    /// The interface it runs on (`InterfaceName`).
    pub interface: String,
    /// Its router (`Router`); none for a service without one.
    pub router: Option<Ipv4Addr>,
    /// The router's link-layer address as configd resolved it
    /// (`ARPResolvedHardwareAddress`); none until it has.
    pub router_lladdr: Option<[u8; 6]>,
    /// The DNS domain the network publishes (`DomainName` of the service's
    /// `/DNS` key, DHCP option 15); none when it publishes none.
    pub domain: Option<String>,
}

/// An opaque `SCDynamicStore` session.
#[repr(C)]
struct SCDynamicStoreOpaque {
    _private: [u8; 0],
}

type SCDynamicStoreRef = *const SCDynamicStoreOpaque;

type SCDynamicStoreCallBack =
    Option<unsafe extern "C" fn(SCDynamicStoreRef, CFArrayRef, *mut c_void)>;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    /// A dynamic store session (the Create rule: the caller releases it);
    /// NULL on failure.
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callout: SCDynamicStoreCallBack,
        context: *mut c_void,
    ) -> SCDynamicStoreRef;

    /// The keys matching a pattern, a `CFArray` of `CFString` (the Copy
    /// rule); NULL on failure.
    fn SCDynamicStoreCopyKeyList(store: SCDynamicStoreRef, pattern: CFStringRef) -> CFArrayRef;

    /// A key's value (the Copy rule); NULL when the key is absent.
    fn SCDynamicStoreCopyValue(store: SCDynamicStoreRef, key: CFStringRef) -> CFPropertyListRef;
}

/// An open dynamic store session, released when dropped.
struct Store(SCDynamicStoreRef);

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the non-null reference `SCDynamicStoreCreate`
        // returned under the Create rule, so this process owns one
        // reference to it, released exactly once, here.
        unsafe { CFRelease(self.0.cast()) };
    }
}

fn configd(fault: ConfigdFault) -> MacsysError {
    MacsysError::Configd { fault }
}

fn open() -> Result<Store, MacsysError> {
    let name = CFString::from_static_string("mooring");
    // SAFETY: `name` is a live CFString for the whole call, which only
    // reads it; no callout and a null context ask for no notifications.
    let store = unsafe {
        SCDynamicStoreCreate(
            kCFAllocatorDefault,
            name.as_concrete_TypeRef(),
            None,
            ptr::null_mut(),
        )
    };
    if store.is_null() {
        return Err(configd(ConfigdFault::StoreUnavailable));
    }
    Ok(Store(store))
}

/// The keys matching `pattern`, each checked to be a string when read.
fn keys(store: &Store, pattern: &'static str) -> Result<CFArray<CFType>, MacsysError> {
    let pattern = CFString::from_static_string(pattern);
    // SAFETY: `store.0` is an open session and `pattern` a live CFString
    // for the whole call, which only reads them.
    let keys = unsafe { SCDynamicStoreCopyKeyList(store.0, pattern.as_concrete_TypeRef()) };
    if keys.is_null() {
        return Err(configd(ConfigdFault::KeyListUnavailable));
    }
    // SAFETY: `keys` is a non-null CFArray owned by this process under the
    // Copy rule; the wrapper releases it when dropped.
    Ok(unsafe { CFArray::<CFType>::wrap_under_create_rule(keys) })
}

/// The dictionary stored under `key`, or `None` when the key is absent.
fn dictionary(
    store: &Store,
    key: &CFString,
) -> Result<Option<CFDictionary<CFString, CFType>>, MacsysError> {
    // SAFETY: `store.0` is an open session and `key` a live CFString for
    // the whole call, which only reads them.
    let value = unsafe { SCDynamicStoreCopyValue(store.0, key.as_concrete_TypeRef()) };
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: `value` is a non-null CFType owned by this process under the
    // Copy rule; the wrapper releases it when dropped.
    let value = unsafe { CFType::wrap_under_create_rule(value) };
    if !value.instance_of::<CFDictionary>() {
        return Err(configd(ConfigdFault::NotADictionary));
    }
    // SAFETY: the value's type was checked to be a dictionary just above;
    // under the Get rule this wrapper retains a reference of its own and
    // releases it when dropped, while `value` releases the Copy rule's.
    let dictionary = unsafe {
        CFDictionary::<CFString, CFType>::wrap_under_get_rule(value.as_CFTypeRef().cast())
    };
    Ok(Some(dictionary))
}

/// The string under `key`, or `None` when the key is absent.
fn text(
    dictionary: &CFDictionary<CFString, CFType>,
    key: &'static str,
) -> Result<Option<String>, MacsysError> {
    let Some(value) = dictionary.find(CFString::from_static_string(key)) else {
        return Ok(None);
    };
    let text = value
        .downcast::<CFString>()
        .ok_or(configd(ConfigdFault::NotAString))?;
    Ok(Some(text.to_string()))
}

/// Parses a link-layer address as configd prints it: six hexadecimal
/// octets of one or two digits each, in either case, separated by colons.
pub(crate) fn link_layer_address(text: &str) -> Option<[u8; 6]> {
    let octets: Vec<u8> = text
        .split(':')
        .map(|octet| {
            if octet.is_empty() || octet.len() > 2 {
                return None;
            }
            u8::from_str_radix(octet, 16).ok()
        })
        .collect::<Option<_>>()?;
    <[u8; 6]>::try_from(octets).ok()
}

/// Every IPv4 service configd publishes, in the store's order. A service
/// whose key vanished between the key list and its read is no attachment
/// and is left out; anything else that is not as configd documents it is
/// `Configd{fault}`, so no service is read as something it is not.
pub fn ipv4_services() -> Result<Vec<Ipv4Service>, MacsysError> {
    let store = open()?;
    let mut services = Vec::new();
    for key in keys(&store, IPV4_SERVICE_KEYS)?.iter() {
        let key = key
            .downcast::<CFString>()
            .ok_or(configd(ConfigdFault::NotAString))?;
        let Some(service) = dictionary(&store, &key)? else {
            continue;
        };
        let interface =
            text(&service, "InterfaceName")?.ok_or(configd(ConfigdFault::InterfaceNameMissing))?;
        let router = text(&service, "Router")?
            .map(|text| {
                text.parse::<Ipv4Addr>()
                    .map_err(|_| configd(ConfigdFault::Router))
            })
            .transpose()?;
        let router_lladdr = text(&service, "ARPResolvedHardwareAddress")?
            .map(|text| link_layer_address(&text).ok_or(configd(ConfigdFault::HardwareAddress)))
            .transpose()?;
        let key_text = key.to_string();
        let service_prefix = key_text
            .strip_suffix(IPV4_SUFFIX)
            .ok_or(configd(ConfigdFault::UnexpectedKey))?;
        let domain = match dictionary(&store, &CFString::new(&format!("{service_prefix}/DNS")))? {
            Some(dns) => text(&dns, "DomainName")?,
            None => None,
        };
        services.push(Ipv4Service {
            interface,
            router,
            router_lladdr,
            domain,
        });
    }
    Ok(services)
}
