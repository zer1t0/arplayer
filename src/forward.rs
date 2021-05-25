use crate::args;
use sysctl::Ctl;
use sysctl::Sysctl;

use log::info;

pub fn main_forward(args: args::forward::Arguments) -> Result<(), String> {
    match args.enable {
        None => println!("{}", get_ip_forward()?),
        Some(enable) => {
            if enable {
                enable_ip_forward()?;
                info!("{} = {}", CTL_FORWARD, get_ip_forward()?);
            } else {
                disable_ip_forward()?;
                info!("{} = {}", CTL_FORWARD, get_ip_forward()?);
            }
        }
    }

    return Ok(());
}

const CTL_FORWARD: &str = "net.ipv4.ip_forward";

pub fn get_ip_forward() -> Result<String, String> {
    let ctl = Ctl::new(CTL_FORWARD).unwrap();
    let value = ctl
        .value_string()
        .map_err(|e| format!("Error retrieving IP forward value: {}", e))?;

    return Ok(value);
}

pub fn set_ip_forward(value: &str) -> Result<(), String> {
    let ctl = Ctl::new(CTL_FORWARD).unwrap();
    ctl.set_value_string(value)
        .map_err(|e| format!(": {}", e))?;
    return Ok(());
}

pub fn enable_ip_forward() -> Result<(), String> {
    set_ip_forward("1").map_err(|e| format!("Error enabling IP forward: {}", e))
}

pub fn disable_ip_forward() -> Result<(), String> {
    set_ip_forward("0")
        .map_err(|e| format!("Error disabling IP forward: {}", e))
}
