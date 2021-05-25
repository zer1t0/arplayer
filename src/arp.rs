use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{
    EtherTypes, EthernetPacket, MutableEthernetPacket,
};
use pnet::packet::Packet;
use pnet::{
    datalink::{
        self, Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr,
        NetworkInterface,
    },
    ipnetwork::{IpNetwork, Ipv4Network},
};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub fn request_arp(
    iface: &NetworkInterface,
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    timeout: Duration,
) -> Result<MacAddr, String> {
    let ethernet_packet = ether_arp_request(target_ip, source_ip, source_mac);

    let mut config = Config::default();
    config.read_timeout = Some(timeout);

    let (mut sender, mut receiver) = new_ether_channel(iface, config)?;

    sender
        .send_to(ethernet_packet.packet(), None)
        .ok_or("Error sending packet")?
        .map_err(|e| format!("Error sending packet: {}", e))?;

    let timeout = timeout;

    let start_time = Instant::now();
    loop {
        let now = Instant::now();
        if now.duration_since(start_time) > timeout {
            return Err(format!("Error receiving packet: Timed out"));
        }
        let buf = receiver
            .next()
            .map_err(|e| format!("Error receiving packet: {}", e))?;
        if !is_arp(buf) {
            continue;
        }

        let arp = ArpPacket::new(
            &buf[MutableEthernetPacket::minimum_packet_size()..],
        )
        .unwrap();

        if is_arp_reply_for(&arp, target_ip) {
            return Ok(arp.get_sender_hw_addr());
        }
    }
}

pub fn new_ether_channel(
    iface: &NetworkInterface,
    config: Config,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), String> {
    let (sender, receiver) = match datalink::channel(iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(format!("Error creating channel: Unknown channel type"))
        }
        Err(e) => return Err(format!("Error creating channel: {}", e)),
    };

    return Ok((sender, receiver));
}

pub fn is_arp(buf: &[u8]) -> bool {
    let ethernet = match EthernetPacket::new(&buf[..]) {
        Some(ether) => ether,
        None => {
            return false;
        }
    };

    return ethernet.get_ethertype() == EtherTypes::Arp;
}

fn is_arp_reply_for(arp: &ArpPacket, target_ip: Ipv4Addr) -> bool {
    return arp.get_operation() == ArpOperations::Reply
        && arp.get_sender_proto_addr() == target_ip;
}

pub fn get_iface_ipv4_network(
    iface: &NetworkInterface,
) -> Option<&Ipv4Network> {
    iface.ips.iter().find(|ip| ip.is_ipv4()).map(|ip| match ip {
        IpNetwork::V4(net) => net,
        _ => unreachable!(),
    })
}

pub fn get_iface_ipv4(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    return get_iface_ipv4_network(iface).map(|net| net.ip());
}

pub fn new_ether_arp_reply<'a>(
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
) -> EthernetPacket<'a> {
    let arp_reply = new_arp_reply(target_ip, target_mac, source_ip, source_mac);
    let ether_packet = new_ether_arp(target_mac, source_mac, &arp_reply);

    return ether_packet;
}

pub fn ether_arp_request<'a>(
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
) -> EthernetPacket<'a> {
    let arp_packet = arp_request(target_ip, source_ip, source_mac);
    let ethernet_packet = ether_arp_broadcast(source_mac, &arp_packet);
    return ethernet_packet;
}

pub fn ether_arp_broadcast<'a>(
    source_mac: MacAddr,
    arp_packet: &ArpPacket<'a>,
) -> EthernetPacket<'a> {
    return new_ether_arp(MacAddr::broadcast(), source_mac, arp_packet);
}

pub fn new_ether_arp<'a>(
    target_mac: MacAddr,
    source_mac: MacAddr,
    arp_packet: &ArpPacket<'a>,
) -> EthernetPacket<'a> {
    let ethernet_buffer = [0u8; 42];
    let mut ethernet_packet =
        MutableEthernetPacket::owned(ethernet_buffer.to_vec()).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    return ethernet_packet.consume_to_immutable();
}

pub fn arp_request<'a>(
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
) -> ArpPacket<'a> {
    let arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::owned(arp_buffer.to_vec()).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    return arp_packet.consume_to_immutable();
}

pub fn new_arp_reply<'a>(
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
) -> ArpPacket<'a> {
    let arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::owned(arp_buffer.to_vec()).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);

    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    return arp_packet.consume_to_immutable();
}
