/// IpAddr `is_global` implementation (for use with stable rust compiler)
/// The code is copied from STD

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub trait IpAddrExt {
    fn is_global(&self) -> bool;
}

impl IpAddrExt for IpAddr {
    fn is_global(&self) -> bool {
        match self {
            IpAddr::V4(ip) => IpAddrExt::is_global(ip),
            IpAddr::V6(ip) => IpAddrExt::is_global(ip),
        }
    }
}

impl IpAddrExt for Ipv4Addr {
    fn is_global(&self) -> bool {
        !(self.octets()[0] == 0 // "This network"
            || self.is_private()
            // NOTE, this line replaces `self.is_shared()`
            || self.octets()[0] == 100 && (self.octets()[1] & 0b1100_0000 == 0b0100_0000)
            || self.is_loopback()
            || self.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // .9 and .10 are documented as globally reachable so they're excluded
            || (
                self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0
                    && self.octets()[3] != 9 && self.octets()[3] != 10
            )
            || self.is_documentation()
            // NOTE, this line replaces `self.is_benchmarking()` 
            || self.octets()[0] == 198 && (self.octets()[1] & 0xfe) == 18
            // NOTE, this line replaces `self.is_reserved()`
            || self.octets()[0] & 240 == 240 && !self.is_broadcast()
            || self.is_broadcast())
    }
}
impl IpAddrExt for Ipv6Addr {
    fn is_global(&self) -> bool {
        !(self.is_unspecified()
            || self.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(self.segments(), [0x2002, _, _, _, _, _, _, _])
            // NOTE, this line replaces `self.is_documentation()`
            || matches!(self.segments(), [0x2001, 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..])
            // Segment Routing (SRv6) SIDs (`5f00::/16`)
            || matches!(self.segments(), [0x5f00, ..])
            || self.is_unique_local()
            || self.is_unicast_link_local())
    }
}
