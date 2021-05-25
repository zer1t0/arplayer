mod helpers;
pub mod reply;
pub mod scan;
pub mod spoof;
pub mod forward;

use clap::{App, AppSettings};

fn args() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommand(scan::command())
        .subcommand(reply::command())
        .subcommand(spoof::command())
        .subcommand(forward::command())
}

pub enum Arguments {
    Reply(reply::Arguments),
    Scan(scan::Arguments),
    Spoof(spoof::Arguments),
    Forward(forward::Arguments),
}

impl Arguments {
    pub fn parse_args() -> Self {
        let matches = args().get_matches();

        match matches.subcommand_name().unwrap() {
            name @ forward::COMMAND_NAME => {
                return Arguments::Forward(forward::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }

            name @ reply::COMMAND_NAME => {
                return Arguments::Reply(reply::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }

            name @ scan::COMMAND_NAME => {
                return Arguments::Scan(scan::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }

            name @ spoof::COMMAND_NAME => {
                return Arguments::Spoof(spoof::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }

            _ => unreachable!("Unknown command"),
        }
    }
}
