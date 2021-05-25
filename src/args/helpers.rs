use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::Ipv4Network;
use pnet::util::MacAddr;
use std::{net::Ipv4Addr, str::FromStr};

pub fn is_u64(v: String) -> Result<(), String> {
    v.parse::<u64>().map_err(|_| {
        format!(
            "Incorrect value '{}' must be an unsigned integer of 64 bits (u64)",
            v
        )
    })?;

    return Ok(());
}

pub fn is_mac(v: String) -> Result<(), String> {
    match MacAddr::from_str(&v) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is a valid MAC address", v)),
    }
}

pub fn is_interface(v: String) -> Result<(), String> {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == v);

    if iface.is_none() {
        return Err(format!("Interface '{}' not found in the system", v));
    }

    return Ok(());
}

pub fn is_ip_or_net(v: String) -> Result<(), String> {
    let ip = v.parse::<Ipv4Addr>();
    if ip.is_ok() {
        return Ok(());
    }

    let net = v.parse::<Ipv4Network>();
    if net.is_ok() {
        return Ok(());
    }

    return Err(format!("'{}' is not a valid IPv4 nor range", v));
}

pub fn is_ip(v: String) -> Result<(), String> {
    v.parse::<Ipv4Addr>()
        .map_err(|_| format!("'{}' is not a valid IPv4", v))?;
    return Ok(());
}

pub fn lookup_interface(iface_name: &str) -> Option<NetworkInterface> {
    return datalink::interfaces()
        .into_iter()
        .find(|iface| &iface.name == iface_name);
}
