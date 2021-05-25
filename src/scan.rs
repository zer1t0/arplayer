use crate::args::{self, scan::Target};
use crate::arp;
use log::{debug, info};
use pnet::ipnetwork::Ipv4Network;
use threadpool::ThreadPool;

pub fn main_scan(args: args::scan::Arguments) -> Result<(), String> {
    let pool = ThreadPool::new(args.workers as usize);

    let timeout = args.timeout;
    let iface_ipv4_net =
        arp::get_iface_ipv4_network(&args.iface).ok_or_else(|| {
            format!(
                "Unable to get the Ipv4 address of {} interface",
                args.iface.name
            )
        })?;
    let source_ip = iface_ipv4_net.ip();
    let source_mac = (&args.iface)
        .mac
        .ok_or_else(|| {
            format!("Unable to get the MAC address of {} interface", args.iface)
        })?
        .clone();

    let ips = match args.target {
        Some(t) => match t {
            Target::Ip(ip) => {
                info!("Scanning {}", ip);
                Ipv4Network::new(ip, 32).unwrap()
            }
            Target::Net(net) => {
                info!("Scanning {}", net);
                net
            }
        }
        .iter(),
        None => {
            info!("Scanning {}", iface_ipv4_net);
            iface_ipv4_net.iter()
        }
    };

    for target_ip in ips {
        let iface = args.iface.clone();

        pool.execute(move || {
            match arp::request_arp(
                &iface, target_ip, source_ip, source_mac, timeout,
            ) {
                Ok(target_mac) => println!("{} {}", target_ip, target_mac),
                Err(e) => debug!("{}: {}", target_ip, e),
            }
        });
    }

    pool.join();

    return Ok(());
}
