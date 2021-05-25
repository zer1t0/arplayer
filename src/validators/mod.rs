use pnet::{packet::arp::ArpPacket, util::MacAddr};
use std::ops::{BitAnd, Not};
use std::{collections::HashSet, net::Ipv4Addr};

pub type Validator = Box<dyn ValidatorTrait>;

pub trait ValidatorTrait: Sync + Send {
    fn is_valid_arp(&self, arp_packet: &ArpPacket) -> bool;
}

impl BitAnd for Validator {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        return AndValidator::new(vec![self, rhs]);
    }
}

impl BitAnd<Option<Validator>> for Validator {
    type Output = Self;

    fn bitand(self, rhs: Option<Self>) -> Self {
        match rhs {
            Some(v) => self & v,
            None => self,
        }
    }
}

impl Not for Validator {
    type Output = Self;

    fn not(self) -> Validator {
        return NotValidator::new(self);
    }
}

pub struct NotValidator {
    v_1: Validator,
}

impl NotValidator {
    pub fn new(v_1: Validator) -> Validator {
        return Box::new(Self { v_1 });
    }
}

impl ValidatorTrait for NotValidator {
    fn is_valid_arp(&self, arp_packet: &ArpPacket) -> bool {
        return !self.v_1.is_valid_arp(arp_packet);
    }
}

pub struct AndValidator {
    sub_vs: Vec<Validator>,
}

impl AndValidator {
    pub fn new(sub_vs: Vec<Validator>) -> Validator {
        return Box::new(Self { sub_vs });
    }
}

impl ValidatorTrait for AndValidator {
    fn is_valid_arp(&self, arp_packet: &ArpPacket) -> bool {
        for verificator in self.sub_vs.iter() {
            if !verificator.is_valid_arp(arp_packet) {
                return false;
            }
        }
        return true;
    }
}

pub struct SrcIpValidator {
    ips: HashSet<Ipv4Addr>,
}

impl SrcIpValidator {
    pub fn new(ips: HashSet<Ipv4Addr>) -> Validator {
        return Box::new(Self { ips });
    }
}

impl ValidatorTrait for SrcIpValidator {
    fn is_valid_arp(&self, arp_packet: &ArpPacket) -> bool {
        return self.ips.contains(&arp_packet.get_sender_proto_addr());
    }
}

pub struct DstIpValidator {
    ips: HashSet<Ipv4Addr>,
}

impl DstIpValidator {
    pub fn new(ips: HashSet<Ipv4Addr>) -> Validator {
        return Box::new(Self { ips });
    }
}

impl ValidatorTrait for DstIpValidator {
    fn is_valid_arp(&self, arp_packet: &ArpPacket) -> bool {
        return self.ips.contains(&arp_packet.get_target_proto_addr());
    }
}

pub struct SrcMacValidator {
    macs: HashSet<MacAddr>,
}

impl SrcMacValidator {
    pub fn new_one(mac: MacAddr) -> Validator {
        let mut macs = HashSet::new();
        macs.insert(mac);
        return Self::new(macs);
    }
    pub fn new(macs: HashSet<MacAddr>) -> Validator {
        return Box::new(Self { macs });
    }
}

impl ValidatorTrait for SrcMacValidator {
    fn is_valid_arp(&self, arp_packet: &ArpPacket) -> bool {
        return self.macs.contains(&arp_packet.get_sender_hw_addr());
    }
}
