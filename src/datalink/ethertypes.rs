/// Common EtherTypes in a Ethernet header.
/// 
/// Most are unused and have fallen out of fashion.
/// 
/// See: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
pub struct EtherTypes;

#[allow(non_upper_case_globals)]
impl EtherTypes {
    /// Address Resolution Protocol (ARP).
    pub const ARP: u16 = 0x806;
    /// Reverse Address Resolution Protocol (RARP).
    pub const RARP: u16 = 0x8035;
    /// Internet Protocol version 4 (IPv4).
    pub const IPv4: u16 = 0x800;
    /// Internet Protocol version 6 (IPv6).
    pub const IPv6: u16 = 0x86dd;
    /// VLAN-tagged frame (VLAN).
    pub const VLAN: u16 = 0x8100;
    /// Wake-on-LAN.
    pub const WakeOnLAN: u16 = 0x0842;
    /// Precision Time Protocol (PTP).
    pub const PTP: u16 = 0x88f7;
    /// Provider Bridging (IEEE 802.1ad).
    pub const PBridge: u16 = 0x88a8;
    /// Q-in-Q VLAN Tagging (IEEE 802.1Q).
    pub const QinQ: u16 = 0x9100;
    /// Ethernet Flow Control (IEEE 802.3x).
    pub const FlowControl: u16 = 0x8808;

    pub fn get_ethertype(ether_type: u16) -> &'static str {
        match ether_type {
            Self::ARP => "ARP",
            Self::RARP => "RARP",
            Self::IPv4 => "IPv4",
            Self::IPv6 => "IPv6",
            Self::VLAN => "VLAN",
            Self::WakeOnLAN => "Wake-on-LAN",
            Self::PTP => "PTP",
            Self::PBridge => "Provider Bridging",
            Self::QinQ => "Q-in-Q VLAN Tagging",
            Self::FlowControl => "Ethernet Flow Control",
            _ => "Unknown",
        }
    }
}
