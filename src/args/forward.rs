use clap::{App, Arg, ArgMatches, SubCommand};

pub const COMMAND_NAME: &str = "forward";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME).about("Enable/Disable IP forwarding")
        .arg(
            Arg::with_name("enable")
                .short("e")
                .long("enable")
                .help("Enable IP forwarding"),
        )
        .arg(
            Arg::with_name("disable")
                .short("d")
                .long("disable")
                .help("Disable IP forwarding")
                .conflicts_with("enable"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub struct Arguments {
    pub enable: Option<bool>,
    pub verbosity: usize,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {

        let enable = if matches.is_present("enable") {
            Some(true)
        } else if matches.is_present("disable") {
            Some(false)
        } else {
            None
        };

        Self {
            enable,
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}
