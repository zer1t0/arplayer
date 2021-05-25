use std::{collections::HashSet, net::Ipv4Addr, time::Duration};

use clap::{App, Arg, ArgMatches, SubCommand, Values};
use pnet::{datalink::NetworkInterface, ipnetwork::Ipv4Network};

use super::helpers;

pub const COMMAND_NAME: &str = "spoof";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Spoof ARP packets")
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
            Arg::with_name("victim-ip")
                .required(true)
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_ip_or_net)
                .help("IP of the victim"),
        )
        .arg(
            Arg::with_name("gw-ip")
                .required(true)
                .takes_value(true)
                .validator(helpers::is_ip)
                .help("IP to impersonate"),
        )
        .arg(
            Arg::with_name("fake-ip")
                .long("fake-ip")
                .short("f")
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("IP to poison the ARP tables. If none, the IP of this machine will be used")
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .short("t")
                .takes_value(true)
                .default_value("5000")
                .value_name("millis")
                .validator(helpers::is_u64)
                .help("Timeout for requests"),
        )
        .arg(
            Arg::with_name("delay")
                .long("delay")
                .short("d")
                .takes_value(true)
                .default_value("1000")
                .value_name("millis")
                .validator(helpers::is_u64)
                .help("Delay between ARP spoof packets"),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .short("c")
                .takes_value(true)
                .validator(helpers::is_u64)
                .help("Number of ARP replies to send. If none, it won't stop until Ctrl-C"),
        )
        .arg(
            Arg::with_name("no-recover")
                .long("no-recover")
                .short("n")
                .help("Don't try to repair the victims ARP table when finish"),
        )
        .arg(
            Arg::with_name("bidirectional")
                .long("bidirectional")
                .short("b")
                .help("Spoof also the gateway"),
        )
        .arg(
            Arg::with_name("forward")
                .long("forward")
                .short("F")
                .help("Enable IP forwarding"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub iface: NetworkInterface,
    pub victim_ips: HashSet<Ipv4Addr>,
    pub gw_ip: Ipv4Addr,
    pub fake_ip: Option<Ipv4Addr>,
    pub delay: Duration,
    pub timeout: Duration,
    pub verbosity: usize,
    pub recover: bool,
    pub count: Option<u64>,
    pub bidirectional: bool,
    pub forward: bool,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        Self {
            iface,
            victim_ips: parse_victim_ips(
                matches.values_of("victim-ip").unwrap(),
            ),
            gw_ip: matches
                .value_of("gw-ip")
                .map(|ip| ip.parse().unwrap())
                .unwrap(),
            fake_ip: matches.value_of("fake-ip").map(|ip| ip.parse().unwrap()),
            verbosity: matches.occurrences_of("verbosity") as usize,
            timeout: Duration::from_millis(
                matches.value_of("timeout").unwrap().parse().unwrap(),
            ),
            delay: Duration::from_millis(
                matches.value_of("delay").unwrap().parse().unwrap(),
            ),
            recover: !matches.is_present("no-recover"),
            bidirectional: matches.is_present("bidirectional"),
            forward: matches.is_present("forward"),
            count: matches.value_of("count").map(|c| c.parse().unwrap()),
        }
    }
}

fn parse_victim_ips<'a>(ips_nets: Values) -> HashSet<Ipv4Addr> {
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
