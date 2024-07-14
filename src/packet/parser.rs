use crate::{
    datalink::{
        arp::ArpReader,
        ethernet::{EthernetReader, ETHERNET_MIN_FRAME_LENGTH},
    },
    misc::{EtherType, Icmpv4Type, Icmpv6Type, IpProtocol},
    network::{
        checksum::{ipv4_pseudo_header, ipv6_pseudo_header, verify_internet_checksum},
        icmpv4::{Icmpv4Reader, ICMPV4_MAX_VALID_CODE},
        icmpv6::Icmpv6Reader,
        ipv4::{IPv4Reader, IPV4_MIN_HEADER_LENGTH},
        ipv6::IPv6Reader,
    },
    transport::{
        tcp::{TcpReader, TCP_MIN_HEADER_LENGTH},
        udp::UdpReader,
    },
};

/// A zero-copy packet parser.
#[derive(Debug)]
pub struct PacketParser<'a> {
    pub ethernet: Option<EthernetReader<'a>>,
    pub arp: Option<ArpReader<'a>>,
    pub ipv4: Option<IPv4Reader<'a>>,
    pub ipv6: Option<IPv6Reader<'a>>,
    pub tcp: Option<TcpReader<'a>>,
    pub udp: Option<UdpReader<'a>>,
    pub icmpv4: Option<Icmpv4Reader<'a>>,
    pub icmpv6: Option<Icmpv6Reader<'a>>,
}

impl<'a> PacketParser<'a> {
    /// Parses a raw Ethernet frame.
    ///
    /// Is strict about what input it accepts.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ETHERNET_MIN_FRAME_LENGTH {
            return Err("Slice needs to be least 64 bytes long to be a valid Ethernet frame.");
        }

        let reader = EthernetReader::new(bytes)?;
        let header_len = reader.header_len();
        let ethertype = reader.ethertype();

        let mut parser = PacketParser {
            arp: None,
            ethernet: Some(reader),
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            icmpv4: None,
            icmpv6: None,
        };

        match EtherType::from(ethertype) {
            EtherType::Arp => parser.parse_arp(&bytes[header_len..])?,
            EtherType::Ipv4 => parser.parse_ipv4(&bytes[header_len..])?,
            EtherType::Ipv6 => parser.parse_ipv6(&bytes[header_len..])?,
            EtherType::Unknown(_) => return Err("Unknown or unsupported EtherType"),
        }

        parser.verify_checksums()?;

        Ok(parser)
    }

    /// Parses an ARP header.
    ///
    /// ARP was originally designed for Ethernet, IPv4 and MAC addresses.
    ///
    /// Theoretically, it can also be used with other combinations of protocols.
    #[inline]
    pub fn parse_arp(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = ArpReader::new(bytes)?;

        if reader.oper() > 2 {
            return Err("ARP operation field is invalid, expected request (1) or reply (2).");
        }

        self.arp = Some(reader);

        Ok(())
    }

    /// Parses a IPv4 header.
    #[inline]
    pub fn parse_ipv4(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = IPv4Reader::new(bytes)?;

        if reader.version() != 4 {
            return Err("IPv4 version field is invalid. Expected version 4.");
        }

        let protocol = reader.protocol();
        let total_length = reader.total_length();
        let header_len = reader.header_len();
        let packet_len = bytes.len();

        if header_len < IPV4_MIN_HEADER_LENGTH {
            return Err("IPv4 IHL field is invalid. Indicated header length is too short.");
        }

        if packet_len < header_len {
            return Err("IPv4 header length is invalid. Indicated header length is too long.");
        }

        if packet_len != total_length as usize {
            return Err("IPv4 total length field is invalid. Does not match actual length.");
        }

        self.ipv4 = Some(reader);

        match IpProtocol::from(protocol) {
            IpProtocol::Tcp => self.parse_tcp(&bytes[header_len..])?,
            IpProtocol::Udp => self.parse_udp(&bytes[header_len..])?,
            IpProtocol::Icmpv4 => self.parse_icmpv4(&bytes[header_len..])?,
            _ => return Err("Unknown IPv4 Protocol."),
        }

        Ok(())
    }

    #[inline]
    pub fn parse_ipv6(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = IPv6Reader::new(bytes)?;

        if reader.version() != 6 {
            return Err("IPv6 version field is invalid. Expected version 6.");
        }

        let header_len = reader.header_len();
        let protocol = reader.next_header();

        self.ipv6 = Some(reader);

        match IpProtocol::from(protocol) {
            IpProtocol::Tcp => self.parse_tcp(&bytes[header_len..])?,
            IpProtocol::Udp => self.parse_udp(&bytes[header_len..])?,
            IpProtocol::Icmpv6 => self.parse_icmpv6(&bytes[header_len..])?,
            _ => return Err("Unknown IPv6 Protocol."),
        }

        Ok(())
    }

    /// Parses a TCP header.
    #[inline]
    pub fn parse_tcp(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = TcpReader::new(bytes)?;

        if reader.header_len() < TCP_MIN_HEADER_LENGTH {
            return Err("TCP data offset field is invalid. Indicated header length is too short.");
        }

        if reader.flags() == 0 {
            return Err("TCP flags field is invalid.");
        }

        self.tcp = Some(reader);

        Ok(())
    }

    /// Parses a UDP header.
    #[inline]
    pub fn parse_udp(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = UdpReader::new(bytes)?;

        let header_len = reader.header_len();
        let payload_len = reader.payload().len();
        let length_field = reader.length() as usize;

        if length_field != header_len + payload_len {
            return Err("UDP length field is invalid. Does not match actual length.");
        }

        self.udp = Some(reader);

        Ok(())
    }

    /// Parses an ICMPv4 header.
    #[inline]
    pub fn parse_icmpv4(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = Icmpv4Reader::new(bytes)?;

        if Icmpv4Type::from(reader.icmp_type()) == Icmpv4Type::Unknown {
            return Err("ICMPv4 type field is invalid.");
        }

        if reader.icmp_code() > ICMPV4_MAX_VALID_CODE {
            return Err("ICMPv4 code field is invalid.");
        }

        self.icmpv4 = Some(reader);

        Ok(())
    }

    /// Parses an ICMPv6 header.
    #[inline]
    pub fn parse_icmpv6(&mut self, _bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = Icmpv6Reader::new(_bytes)?;

        if Icmpv6Type::from(reader.icmp_type()) == Icmpv6Type::Unknown {
            return Err("ICMPv6 type field is invalid.");
        }

        self.icmpv6 = Some(reader);

        Ok(())
    }

    /// Verifies the checksums of encapsulated headers.
    #[inline]
    pub fn verify_checksums(&self) -> Result<(), &'static str> {
        let pseudo = if let Some(ipv4) = &self.ipv4 {
            if !verify_internet_checksum(ipv4.header(), 0) {
                return Err("IPv4 checksum is invalid.");
            }
            Some((ipv4.src_ip(), ipv4.dest_ip(), ipv4.protocol()))
        } else {
            self.ipv6
                .as_ref()
                .map(|ipv6| (ipv6.src_addr(), ipv6.dest_addr(), ipv6.next_header()))
        };

        if let Some(tcp) = &self.tcp {
            Self::verify_transport_checksum(tcp.bytes, pseudo)?;
        }

        if let Some(udp) = &self.udp {
            Self::verify_transport_checksum(udp.bytes, pseudo)?;
        }

        if let Some(icmpv4) = &self.icmpv4 {
            if !verify_internet_checksum(icmpv4.bytes, 0) {
                return Err("ICMPv4 checksum is invalid.");
            }
        }

        if let Some(icmpv6) = &self.icmpv6 {
            Self::verify_transport_checksum(icmpv6.bytes, pseudo)?;
        }

        Ok(())
    }

    /// Verifies the checksum of a transport protocol.
    ///
    /// Takes the pseudo header into account.
    #[inline]
    fn verify_transport_checksum(
        bytes: &[u8],
        pseudo: Option<(&[u8], &[u8], u8)>,
    ) -> Result<(), &'static str> {
        let (src, dest, protocol) =
            pseudo.ok_or("Checksum cannot be verified without a pseudo header.")?;

        let pseudo_sum = match src.len() {
            4 => ipv4_pseudo_header(
                src.try_into().unwrap(),  // won't panic
                dest.try_into().unwrap(), // won't panic
                protocol,
                bytes.len(),
            ),
            16 => ipv6_pseudo_header(
                src.try_into().unwrap(),  // won't panic
                dest.try_into().unwrap(), // won't panic
                protocol,
                bytes.len(),
            ),
            _ => return Err("Unsupported IP address length for pseudo header."),
        };

        if !verify_internet_checksum(bytes, pseudo_sum) {
            return Err(match IpProtocol::from(protocol) {
                IpProtocol::Tcp => "TCP checksum is invalid.",
                IpProtocol::Udp => "UDP checksum is invalid.",
                IpProtocol::Icmpv6 => "ICMPv6 checksum is invalid.",
                _ => "Unsupported protocol checksum.",
            });
        }

        Ok(())
    }

    /// Returns the total length of all headers.
    #[inline]
    pub fn header_len(&self) -> usize {
        let mut len = 0;

        if let Some(ethernet) = &self.ethernet {
            len += ethernet.header_len();
        }

        if let Some(arp) = &self.arp {
            len += arp.header_len();
        }

        if let Some(ipv4) = &self.ipv4 {
            len += ipv4.header_len();
        }

        if let Some(ipv6) = &self.ipv6 {
            len += ipv6.header_len();
        }

        if let Some(tcp) = &self.tcp {
            len += tcp.header_len();
        }

        if let Some(udp) = &self.udp {
            len += udp.header_len();
        }

        if let Some(icmpv4) = &self.icmpv4 {
            len += icmpv4.header_len();
        }

        if let Some(icmpv6) = &self.icmpv6 {
            len += icmpv6.header_len();
        }

        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_frame_too_short() {
        // Raw packet data. A valid Ethernet frame needs at least 64 bytes.
        let packet = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 6, 87, 113, 192, 168, 1, 1, 192, 168, 1, 2, 0, 99, 0, 11, 0, 0, 0, 123,
            0, 0, 1, 65, 59, 99, 16, 225, 41, 81, 4, 210,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser fails.
        assert_eq!(
            parser.is_err(),
            true,
            "Slice needs to be least 64 bytes long to be a valid Ethernet frame."
        );
    }

    #[test]
    fn test_vlan_tagged_frame() {
        // Valid VLAN tagged packet (Ethernet II + IPv4 + UDP).
        let packet = [
            // Ethernet header
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Destination MAC
            0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x00, // Source MAC
            0x81, 0x00, // VLAN Ethertype
            0x00, 0x64, // VLAN Tag (priority 0, CFI 0, VLAN ID 100)
            0x08, 0x00, // Ethertype (IPv4)
            // IPv4 header
            0x45, 0x00, 0x00, 0x2e, // Version, IHL, DSCP, ECN, Total Length (46 bytes)
            0x00, 0x00, 0x00, 0x00, // Identification, Flags, Fragment Offset
            0x40, 0x11, 0xf9, 0x6b, // TTL (64), Protocol (UDP), IPv4 Checksum
            0xC0, 0xA8, 0x00, 0x01, // Source IP (192.168.0.1)
            0xC0, 0xA8, 0x00, 0x02, // Destination IP (192.168.0.2)
            // UDP header
            0x04, 0xD2, 0x16, 0x2E, // Source Port (1234), Destination Port (5678)
            0x00, 0x1a, 0x63, 0x66, // Length (26 bytes), UDP Checksum
            // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, // Padding
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the parser has the expected headers.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv4.is_some());
        assert!(unwrapped.udp.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());

        // Unwrap Ethernet II.
        let ethernet = unwrapped.ethernet.unwrap();

        // Ensure the VLAN tagging.
        assert!(ethernet.vlan_tag().is_some());
        assert!(ethernet.double_vlan_tag().is_none());

        // Ensure the VLAN tag is correct.
        assert_eq!(ethernet.vlan_tag().unwrap(), (0x8100, 100));

        // Ensure the EtherType is correct.
        assert_eq!(ethernet.ethertype(), 0x0800);
    }

    #[test]
    fn test_double_vlan_tagged_frame() {
        // Valid double VLAN tagged packet (Ethernet II + IPv4 + UDP).
        let packet = [
            // Ethernet header
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Destination MAC
            0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x00, // Source MAC
            0x88, 0xA8, // Outer VLAN Ethertype
            0x00, 0xC8, // Outer VLAN Tag (priority 0, CFI 0, VLAN ID 200)
            0x81, 0x00, // Inner VLAN Ethertype
            0x00, 0x64, // Inner VLAN Tag (priority 0, CFI 0, VLAN ID 100)
            0x08, 0x00, // Ethertype (IPv4)
            // IPv4 header
            0x45, 0x00, 0x00, 0x2a, // Version, IHL, DSCP, ECN, Total Length (42 bytes)
            0x00, 0x00, 0x00, 0x00, // Identification, Flags, Fragment Offset
            0x40, 0x11, 0xf9, 0x6f, // TTL (64), Protocol (UDP), IPv4 Checksum
            0xC0, 0xA8, 0x00, 0x01, // Source IP (192.168.0.1)
            0xC0, 0xA8, 0x00, 0x02, // Destination IP (192.168.0.2)
            // UDP header
            0x04, 0xD2, 0x16, 0x2E, // Source Port (1234), Destination Port (5678)
            0x00, 0x16, 0x63, 0x6e, // Length (22 bytes), UDP Checksum (0x6366)
            // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, // Padding
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the parser has the expected headers.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv4.is_some());
        assert!(unwrapped.udp.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());

        // Unwrap Ethernet II.
        let ethernet = unwrapped.ethernet.unwrap();

        // Ensure the VLAN tagging.
        assert!(ethernet.vlan_tag().is_none());
        assert!(ethernet.double_vlan_tag().is_some());

        // Ensure the double VLAN tag is correct.
        assert_eq!(
            ethernet.double_vlan_tag().unwrap(),
            ((0x88A8, 200), (0x8100, 100))
        );

        // Ensure the EtherType is correct.
        assert_eq!(ethernet.ethertype(), 0x0800);
    }

    #[test]
    fn test_icmpv4_echo_response() {
        // ICMP echo response (Ethernet + IPv4 + ICMP).
        let packet = [
            0x08, 0x00, 0x20, 0x86, 0x35, 0x4b, 0x00, 0xe0, 0xf7, 0x26, 0x3f, 0xe9, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x54, 0xaa, 0xfb, 0x40, 0x00, 0xfc, 0x01, 0xfa, 0x30, 0x8b, 0x85,
            0xe9, 0x02, 0x8b, 0x85, 0xd9, 0x6e, 0x00, 0x00, 0x45, 0xda, 0x1e, 0x60, 0x00, 0x00,
            0x33, 0x5e, 0x3a, 0xb8, 0x00, 0x00, 0x42, 0xac, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the parser has the expected fields.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv4.is_some());
        assert!(unwrapped.icmpv4.is_some());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());
        assert!(unwrapped.udp.is_none());

        // Unwrap headers.
        let ethernet = unwrapped.ethernet.unwrap();
        let ipv4 = unwrapped.ipv4.unwrap();
        let icmpv4 = unwrapped.icmpv4.unwrap();

        // Ensure the fields are correct.
        assert_eq!(ethernet.ethertype(), 0x0800);
        assert_eq!(ipv4.protocol(), 1);
        assert_eq!(ipv4.checksum(), 0xfa30);
        assert_eq!(icmpv4.icmp_type(), 0);
        assert_eq!(icmpv4.icmp_code(), 0);
        assert_eq!(icmpv4.checksum(), 0x45da);
    }

    #[test]
    fn test_ipv6_icmpv6() {
        // ICMPv6 packet (Ethernet + IPv6 + ICMPv6).
        let packet = [
            0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x60, 0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x87, 0x00,
            0x68, 0xbd, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x60, 0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x01, 0x01, 0x00, 0x00, 0x86, 0x05,
            0x80, 0xda,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the parser has the expected fields.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv6.is_some());
        assert!(unwrapped.icmpv6.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());
        assert!(unwrapped.udp.is_none());

        // Unwrap headers.
        let ethernet = unwrapped.ethernet.unwrap();
        let ipv6 = unwrapped.ipv6.unwrap();
        let icmpv6 = unwrapped.icmpv6.unwrap();

        // Ensure the fields are correct.
        assert_eq!(ethernet.ethertype(), 34525);
        assert_eq!(ipv6.next_header(), 58);
        assert_eq!(icmpv6.icmp_type(), 135);
        assert_eq!(icmpv6.icmp_code(), 0);
    }
}
