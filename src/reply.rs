use crate::args::reply::{IpsVal, MacsVal};
use crate::arp;
use crate::validators::{DstIpValidator, SrcIpValidator, SrcMacValidator};
use crate::{args, validators::Validator};
use pnet::{
    datalink::{Config, NetworkInterface},
    packet::{
        arp::{ArpOperations, ArpPacket},
        ethernet::MutableEthernetPacket,
        Packet,
    },
    util::MacAddr,
};

use log::{debug, info};

pub fn main_reply(args: args::reply::Arguments) -> Result<(), String> {
    let iface = args.iface;
    let my_mac = (&iface).mac.ok_or_else(|| {
        format!("Unable to get the MAC address of {} interface", iface)
    })?;

    let source_mac = match args.mac {
        Some(mac) => mac,
        None => my_mac,
    };

    let arp_validator =
        build_validator(my_mac, args.src_ips, args.src_macs, args.dst_ips);

    reply_to_arp(&iface, source_mac, arp_validator)?;

    return Ok(());
}

fn build_validator(
    my_mac: MacAddr,
    src_ips: Option<IpsVal>,
    src_macs: Option<MacsVal>,
    dst_ips: Option<IpsVal>,
) -> Validator {
    let mut arp_filter = !SrcMacValidator::new_one(my_mac);

    if let Some(src_ips) = src_ips {
        let src_ip_val = match src_ips {
            IpsVal::Filter(ips) => !SrcIpValidator::new(ips),
            IpsVal::Match(ips) => SrcIpValidator::new(ips),
        };
        arp_filter = arp_filter & src_ip_val;
    }

    if let Some(src_macs) = src_macs {
        let src_mac_val = match src_macs {
            MacsVal::Filter(macs) => !SrcMacValidator::new(macs),
            MacsVal::Match(macs) => SrcMacValidator::new(macs),
        };
        arp_filter = arp_filter & src_mac_val;
    }

    if let Some(dst_ips) = dst_ips {
        let dst_ip_val = match dst_ips {
            IpsVal::Filter(ips) => !DstIpValidator::new(ips),
            IpsVal::Match(ips) => DstIpValidator::new(ips),
        };
        arp_filter = arp_filter & dst_ip_val;
    }

    return arp_filter;
}

fn reply_to_arp(
    iface: &NetworkInterface,
    source_mac: MacAddr,
    arp_validator: Validator,
) -> Result<(), String> {
    let (mut sender, mut receiver) =
        arp::new_ether_channel(iface, Config::default()).unwrap();

    loop {
        let buf = receiver
            .next()
            .map_err(|e| format!("Error receiving packet: {}", e))?;
        if !arp::is_arp(buf) {
            continue;
        }

        let arp_msg = ArpPacket::new(
            &buf[MutableEthernetPacket::minimum_packet_size()..],
        )
        .unwrap();

        if arp_msg.get_operation() != ArpOperations::Request {
            continue;
        }

        let sender_mac = arp_msg.get_sender_hw_addr();
        let sender_ip = arp_msg.get_sender_proto_addr();
        let target_ip = arp_msg.get_target_proto_addr();

        if !arp_validator.is_valid_arp(&arp_msg) {
            debug!(
                "Ignore request for {} from {} ({})",
                target_ip, sender_ip, sender_mac
            );
            continue;
        }

        info!(
            "Reply request for {} from {} ({})",
            target_ip, sender_ip, sender_mac
        );

        let target_mac = sender_mac;
        let (source_ip, target_ip) = (target_ip, sender_ip);

        let ether_packet = arp::new_ether_arp_reply(
            target_ip, target_mac, source_ip, source_mac,
        );

        sender
            .send_to(ether_packet.packet(), None)
            .ok_or("Error sending packet")
            .unwrap()
            .map_err(|e| format!("Error sending packet: {}", e))?;

        // println!("{:?}", arp);
    }
}
