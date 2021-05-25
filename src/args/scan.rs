use clap::{App, Arg, ArgMatches, SubCommand};
use pnet::ipnetwork::{Ipv4Network};
use pnet::datalink::NetworkInterface;
use std::{net::Ipv4Addr, time::Duration};

use super::helpers;

pub const COMMAND_NAME: &str = "scan";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("ARP Scan")
        .arg(
            Arg::with_name("iface")
                .long("iface")
                .short("I")
                .required(true)
                .takes_value(true)
                .validator(helpers::is_interface)
                .help("Interface to send the request"),
        )
        .arg(
            Arg::with_name("ip")
                .takes_value(true)
                .validator(helpers::is_ip_or_net)
                .help("Ip or Network to scan, if none, interface network will be scanned"),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .short("t")
                .takes_value(true)
                .default_value("5000")
                .value_name("millis")
                .validator(helpers::is_u64)
                .help("Timeout for ARP requests (to discover victim and spoofed device)"),
        )
        .arg(
            Arg::with_name("workers")
                .long("workers")
                .short("w")
                .takes_value(true)
                .default_value("1")
                .validator(helpers::is_u64)
                .help("Concurrent workers to send requests"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub enum Target {
    Ip(Ipv4Addr),
    Net(Ipv4Network),
}

pub struct Arguments {
    pub iface: NetworkInterface,
    pub target: Option<Target>,
    pub timeout: Duration,
    pub workers: u64,
    pub verbosity: usize,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        Self {
            iface,
            target: matches.value_of("ip").map(|t| parse_target(t)),
            timeout: Duration::from_millis(
                matches.value_of("timeout").unwrap().parse().unwrap(),
            ),
            workers: matches.value_of("workers").unwrap().parse().unwrap(),
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}

fn parse_target(target: &str) -> Target {
    let ip = target.parse::<Ipv4Addr>();
    if ip.is_ok() {
        return Target::Ip(ip.unwrap());
    }

    let net = target.parse::<Ipv4Network>().unwrap();
    return Target::Net(net);
}
