/// Common EtherTypes in a Ethernet header.
/// 
/// Most are unused and have fallen out of fashion.
/// 
/// See: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
#[repr(u16)]
pub enum EtherType {
    ARP = 0x0806,
    IPv4 = 0x0800,
    IPv6 = 0x86dd,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::IPv6,
            other => EtherType::Unknown(other),
        }
    }
}

/// Common IP protocols.
#[repr(u8)]
pub enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            other => IpProtocol::Unknown(other),
        }
    }
}

/// Convert a byte slice to a hex string
/// 
/// Used when debug printing mac addresses to the console.
pub fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
}