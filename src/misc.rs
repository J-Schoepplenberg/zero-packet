use core::fmt::{self};

/// Common EtherTypes.
///
/// See: <https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.>.
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum EtherType {
    Arp = 0x0806,
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::Ipv6,
            other => EtherType::Unknown(other),
        }
    }
}

/// Common IP protocols.
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum IpProtocol {
    Icmpv4 = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
    NoNextHeader = 59,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmpv4,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            59 => IpProtocol::NoNextHeader,
            other => IpProtocol::Unknown(other),
        }
    }
}

/// Common ICMPv4 types.
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum Icmpv4Type {
    EchoReply = 0,
    DestUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSelection = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
    Traceroute = 30,
    Photuris = 40,
    ExtendedEchoRequest = 42,
    ExtendedEchoReply = 43,
    Experimental1 = 253,
    Experimental2 = 254,
    Unknown,
}

impl From<u8> for Icmpv4Type {
    fn from(value: u8) -> Self {
        match value {
            0 => Icmpv4Type::EchoReply,
            3 => Icmpv4Type::DestUnreachable,
            4 => Icmpv4Type::SourceQuench,
            5 => Icmpv4Type::Redirect,
            8 => Icmpv4Type::EchoRequest,
            9 => Icmpv4Type::RouterAdvertisement,
            10 => Icmpv4Type::RouterSelection,
            11 => Icmpv4Type::TimeExceeded,
            12 => Icmpv4Type::ParameterProblem,
            13 => Icmpv4Type::Timestamp,
            14 => Icmpv4Type::TimestampReply,
            15 => Icmpv4Type::InformationRequest,
            16 => Icmpv4Type::InformationReply,
            17 => Icmpv4Type::AddressMaskRequest,
            18 => Icmpv4Type::AddressMaskReply,
            30 => Icmpv4Type::Traceroute,
            40 => Icmpv4Type::Photuris,
            42 => Icmpv4Type::ExtendedEchoRequest,
            43 => Icmpv4Type::ExtendedEchoReply,
            253 => Icmpv4Type::Experimental1,
            254 => Icmpv4Type::Experimental2,
            _ => Icmpv4Type::Unknown,
        }
    }
}

/// Common ICMPv6 types.
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum Icmpv6Type {
    DestUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    Experimental1 = 100,
    Experimental2 = 101,
    EchoRequest = 128,
    EchoReply = 129,
    MldQuery = 130,
    MldReport = 131,
    MldDone = 132,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
    RouterRenumbering = 138,
    IcmpNodeInformationQuery = 139,
    IcmpNodeInformationResponse = 140,
    InverseNeighborDiscoverySolicitation = 141,
    InverseNeighborDiscoveryAdvertisement = 142,
    Mld2Report = 143,
    HomeAgentAddressDiscoveryRequest = 144,
    HomeAgentAddressDiscoveryReply = 145,
    MobilePrefixSolicitation = 146,
    MobilePrefixAdvertisement = 147,
    CertificationPathSolicitation = 148,
    CertificationPathAdvertisement = 149,
    ExperimentalMobilityProtocols = 150,
    MulticastRouterAdvertisement = 151,
    MulticastRouterSolicitation = 152,
    MulticastRouterTermination = 153,
    RplControlMessage = 155,
    Experimental3 = 200,
    Experimental4 = 201,
    Unknown,
}

impl From<u8> for Icmpv6Type {
    fn from(value: u8) -> Self {
        match value {
            1 => Icmpv6Type::DestUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            100 => Icmpv6Type::Experimental1,
            101 => Icmpv6Type::Experimental2,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            130 => Icmpv6Type::MldQuery,
            131 => Icmpv6Type::MldReport,
            132 => Icmpv6Type::MldDone,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::Redirect,
            138 => Icmpv6Type::RouterRenumbering,
            139 => Icmpv6Type::IcmpNodeInformationQuery,
            140 => Icmpv6Type::IcmpNodeInformationResponse,
            141 => Icmpv6Type::InverseNeighborDiscoverySolicitation,
            142 => Icmpv6Type::InverseNeighborDiscoveryAdvertisement,
            143 => Icmpv6Type::Mld2Report,
            144 => Icmpv6Type::HomeAgentAddressDiscoveryRequest,
            145 => Icmpv6Type::HomeAgentAddressDiscoveryReply,
            146 => Icmpv6Type::MobilePrefixSolicitation,
            147 => Icmpv6Type::MobilePrefixAdvertisement,
            148 => Icmpv6Type::CertificationPathSolicitation,
            149 => Icmpv6Type::CertificationPathAdvertisement,
            150 => Icmpv6Type::ExperimentalMobilityProtocols,
            151 => Icmpv6Type::MulticastRouterAdvertisement,
            152 => Icmpv6Type::MulticastRouterSolicitation,
            153 => Icmpv6Type::MulticastRouterTermination,
            155 => Icmpv6Type::RplControlMessage,
            200 => Icmpv6Type::Experimental3,
            201 => Icmpv6Type::Experimental4,
            _ => Icmpv6Type::Unknown,
        }
    }
}

/// Common Extension Header types for IPv6.
#[repr(u8)]
pub enum NextHeader {
    HopByHop = 0,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Routing = 43,
    Fragment = 44,
    Esp = 50,
    AuthHeader = 51,
    NoNextHeader = 59,
    Destination = 60,
    Mobility = 135,
    Unknown,
}

impl From<u8> for NextHeader {
    fn from(value: u8) -> Self {
        match value {
            0 => NextHeader::HopByHop,
            43 => NextHeader::Routing,
            44 => NextHeader::Fragment,
            50 => NextHeader::Esp,
            51 => NextHeader::AuthHeader,
            59 => NextHeader::NoNextHeader,
            60 => NextHeader::Destination,
            135 => NextHeader::Mobility,
            _ => NextHeader::Unknown,
        }
    }
}

/// Workaround for the lack of heap support.
#[inline]
pub fn bytes_to_mac(bytes: &[u8], buffer: &mut [u8]) -> usize {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    let mut buffer_index = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if i != 0 {
            buffer[buffer_index] = b':';
            buffer_index += 1;
        }

        buffer[buffer_index] = HEX_CHARS[(byte >> 4) as usize];
        buffer[buffer_index + 1] = HEX_CHARS[(byte & 0xf) as usize];
        buffer_index += 2;
    }

    buffer_index
}

/// Workaround for the lack of heap support.
#[inline]
pub fn bytes_to_ipv6(bytes: &[u8], buffer: &mut [u8]) -> usize {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    let mut buffer_index = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if i % 2 == 0 && i != 0 {
            buffer[buffer_index] = b':';
            buffer_index += 1;
        }

        buffer[buffer_index] = HEX_CHARS[(byte >> 4) as usize];
        buffer[buffer_index + 1] = HEX_CHARS[(byte & 0xf) as usize];
        buffer_index += 2;
    }

    buffer_index
}

/// Wrapper to format an IP address.
pub struct IpFormatter<'a>(pub &'a [u8]);

impl fmt::Debug for IpFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = self.0;
        write!(f, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }
}
