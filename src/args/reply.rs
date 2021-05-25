use std::net::Ipv4Addr;
use std::{collections::HashSet, str::FromStr};

use clap::{App, Arg, ArgMatches, SubCommand, Values};
use pnet::ipnetwork::Ipv4Network;
use pnet::{datalink::NetworkInterface, util::MacAddr};

use super::helpers;

pub const COMMAND_NAME: &str = "reply";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Reply to ARP requests")
        .arg(
            Arg::with_name("iface")
                .long("iface")
                .short("I")
                .required(true)
                .takes_value(true)
                .validator(helpers::is_interface)
                .help("Interface to listen"),
        )
        .arg(
            Arg::with_name("mac")
                .long("mac")
                .takes_value(true)
                .validator(helpers::is_mac)
                .help("Use the given MAC to answer requests. If none, the interface MAC will be used")
        )
        .arg(
            Arg::with_name("match-src-ips")
                .long("match-src-ips")
                .short("s")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_ip_or_net)
                .help("Reply to ARP request with the given source ips"),
        )
        .arg(
            Arg::with_name("filter-src-ips")
                .long("filter-src-ips")
                .short("S")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_ip_or_net)
                .help("Not reply to ARP request with the given source ips")
                .conflicts_with("match-src-ips"),
        )
        .arg(
            Arg::with_name("match-dst-ips")
                .long("match-dst-ips")
                .short("d")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_ip_or_net)
                .help("Reply to ARP requests that ask for the given ips"),
        )
        .arg(
            Arg::with_name("filter-dst-ips")
                .long("filter-dst-ips")
                .short("D")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_ip_or_net)
                .help("Not reply to ARP requests that ask for the given ips")
                .conflicts_with("match-dst-ips"),
        )
        .arg(
            Arg::with_name("match-src-macs")
                .long("match-src-macs")
                .short("m")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_mac)
                .help("Reply to ARP requests with the given source MACs"),
        )
        .arg(
            Arg::with_name("filter-src-macs")
                .long("filter-src-macs")
                .short("M")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_mac)
                .help("Not reply to ARP requests with the given source MACs")
                .conflicts_with("match-src-macs"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

#[derive(Debug)]
pub enum IpsVal {
    Match(HashSet<Ipv4Addr>),
    Filter(HashSet<Ipv4Addr>),
}

#[derive(Debug)]
pub enum MacsVal {
    Match(HashSet<MacAddr>),
    Filter(HashSet<MacAddr>),
}

#[derive(Debug)]
pub struct Arguments {
    pub iface: NetworkInterface,
    pub mac: Option<MacAddr>,
    pub src_ips: Option<IpsVal>,
    pub src_macs: Option<MacsVal>,
    pub dst_ips: Option<IpsVal>,
    pub verbosity: usize,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        let src_ips = match matches.values_of("match-src-ips") {
            Some(msi) => Some(IpsVal::Match(parse_ips(msi))),
            None => matches
                .values_of("filter-src-ips")
                .map(|fsi| IpsVal::Filter(parse_ips(fsi))),
        };

        let src_macs = match matches.values_of("match-src-macs") {
            Some(msm) => Some(MacsVal::Match(parse_macs(msm))),
            None => matches
                .values_of("filter-src-macs")
                .map(|fsm| MacsVal::Filter(parse_macs(fsm))),
        };

        let dst_ips = match matches.values_of("match-dst-ips") {
            Some(msi) => Some(IpsVal::Match(parse_ips(msi))),
            None => matches
                .values_of("filter-dst-ips")
                .map(|fsi| IpsVal::Filter(parse_ips(fsi))),
        };

        Self {
            iface,
            mac: matches.value_of("mac").map(|s| s.parse().unwrap()),
            src_ips,
            src_macs,
            dst_ips,
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}

fn parse_macs<'a>(macs_str: Values) -> HashSet<MacAddr> {
    let mut macs = HashSet::new();

    for mac_str in macs_str {
        let mac = MacAddr::from_str(mac_str).unwrap();
        macs.insert(mac);
    }
    return macs;
}

fn parse_ips<'a>(ips_nets: Values) -> HashSet<Ipv4Addr> {
    let mut ips = HashSet::new();

    ips_nets
        .into_iter()
        .for_each(|ip_net| match ip_net.parse::<Ipv4Addr>() {
            Ok(ip) => {
                ips.insert(ip);
            }
            Err(_) => {
                let net = ip_net.parse::<Ipv4Network>().unwrap();

                for ip in net.iter() {
                    ips.insert(ip);
                }
            }
        });

    return ips;
}
