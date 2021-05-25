mod args;
mod arp;
mod reply;
mod scan;
mod spoof;
mod validators;
mod forward;

use args::Arguments;
use log::error;
use stderrlog;

pub fn init_log(verbosity: usize) {
    stderrlog::new()
        .module(module_path!())
        .verbosity(verbosity + 1)
        .init()
        .unwrap();
}

fn main() {
    let args = Arguments::parse_args();

    let res = match args {
        Arguments::Reply(args) => {
            init_log(args.verbosity);
            reply::main_reply(args)
        }
        Arguments::Scan(args) => {
            init_log(args.verbosity);
            scan::main_scan(args)
        }
        Arguments::Spoof(args) => {
            init_log(args.verbosity);
            spoof::main_spoof(args)
        }
        Arguments::Forward(args) => {
            init_log(args.verbosity);
            forward::main_forward(args)
        }
    };

    if let Err(e) = res {
        error!("{}", e);
    }
}
