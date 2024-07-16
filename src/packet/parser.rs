use crate::{
    datalink::{
        arp::ArpReader,
        ethernet::{EthernetReader, ETHERNET_MIN_FRAME_LENGTH},
    },
    misc::{EtherType, Icmpv4Type, Icmpv6Type, IpProtocol},
    network::{
        checksum::{pseudo_header, verify_internet_checksum},
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
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let ethernet = EthernetReader::parse(bytes)?;
        let payload = &bytes[ethernet.header_len()..];

        let mut parser = PacketParser {
            ethernet: None,
            arp: None,
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            icmpv4: None,
            icmpv6: None,
        };

        match EtherType::from(ethernet.ethertype()) {
            EtherType::Arp => parser.arp = Some(ArpReader::parse(payload)?),
            EtherType::Ipv4 => {
                let ipv4 = IPv4Reader::parse(payload)?;
                let payload = ipv4.payload();
                match IpProtocol::from(ipv4.protocol()) {
                    IpProtocol::Tcp => parser.tcp = Some(TcpReader::parse(payload)?),
                    IpProtocol::Udp => parser.udp = Some(UdpReader::parse(payload)?),
                    IpProtocol::Icmpv4 => parser.icmpv4 = Some(Icmpv4Reader::parse(payload)?),
                    _ => return Err("Unknown IPv4 Protocol."),
                }
                ipv4.verify_checksum()?;
                parser.ipv4 = Some(ipv4);
            }
            EtherType::Ipv6 => {
                let ipv6 = IPv6Reader::parse(payload)?;
                let payload = ipv6.payload();
                match IpProtocol::from(ipv6.next_header()) {
                    IpProtocol::Tcp => parser.tcp = Some(TcpReader::parse(payload)?),
                    IpProtocol::Udp => parser.udp = Some(UdpReader::parse(payload)?),
                    IpProtocol::Icmpv6 => parser.icmpv6 = Some(Icmpv6Reader::parse(payload)?),
                    _ => return Err("Unknown IPv6 Protocol."),
                }
                ipv6.verify_checksum()?;
                parser.ipv6 = Some(ipv6);
            }
            EtherType::Unknown(_) => return Err("Unknown or unsupported EtherType"),
        }

        parser.ethernet = Some(ethernet);

        Ok(parser)
    }
}

/// Trait to parse a protocol header.
pub trait Parse<'a>: Sized {
    /// Parses the protocol header from the given slice.
    ///
    /// Checks certain fields for validity.
    ///
    /// May fail if any of the fields are deemed invalid.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice containing the raw bytes of the protocol header.
    ///
    /// # Returns
    ///
    /// A result containing the parsed protocol header on success, or a static string error message on failure.
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str>;
}

impl<'a> Parse<'a> for EthernetReader<'a> {
    /// Parses an Ethernet frame from a byte slice.
    ///
    /// Validates that the byte slice is at least the minimum Ethernet frame length.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ETHERNET_MIN_FRAME_LENGTH {
            return Err("Slice needs to be least 64 bytes long to be a valid Ethernet frame.");
        }

        EthernetReader::new(bytes)
    }
}

impl<'a> Parse<'a> for ArpReader<'a> {
    /// Parses an ARP packet from a byte slice.
    ///
    /// Validates the ARP operation field.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = ArpReader::new(bytes)?;

        if reader.oper() > 2 {
            return Err("ARP operation field is invalid, expected request (1) or reply (2).");
        }

        Ok(reader)
    }
}

impl<'a> Parse<'a> for IPv4Reader<'a> {
    /// Parses an IPv4 packet from a byte slice.
    ///
    /// Validates the IPv4 version, header length, total length, and checksum fields.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = IPv4Reader::new(bytes)?;

        if reader.version() != 4 {
            return Err("IPv4 version field is invalid. Expected version 4.");
        }

        let header_len = reader.header_len();
        let packet_len = bytes.len();

        if header_len < IPV4_MIN_HEADER_LENGTH {
            return Err("IPv4 IHL field is invalid. Indicated header length is too short.");
        }

        if packet_len < header_len {
            return Err("IPv4 header length is invalid. Indicated header length is too long.");
        }

        if packet_len != reader.total_length() as usize {
            return Err("IPv4 total length field is invalid. Does not match actual length.");
        }

        if !reader.valid_checksum() {
            return Err("IPv4 checksum is invalid.");
        }

        Ok(reader)
    }
}

impl<'a> Parse<'a> for IPv6Reader<'a> {
    /// Parses an IPv6 packet from a byte slice.
    ///
    /// Validates the IPv6 version field.
    ///
    /// Note: IPv6 does not have a checksum field.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = IPv6Reader::new(bytes)?;

        if reader.version() != 6 {
            return Err("IPv6 version field is invalid. Expected version 6.");
        }

        Ok(reader)
    }
}

impl<'a> Parse<'a> for TcpReader<'a> {
    /// Parses a TCP segment from a byte slice.
    ///
    /// Validates the TCP header length and flags fields.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = TcpReader::new(bytes)?;

        if reader.header_len() < TCP_MIN_HEADER_LENGTH {
            return Err("TCP data offset field is invalid. Indicated header length is too short.");
        }

        if reader.flags() == 0 {
            return Err("TCP flags field is invalid.");
        }

        Ok(reader)
    }
}

impl<'a> Parse<'a> for UdpReader<'a> {
    /// Parses a UDP datagram from a byte slice.
    ///
    /// Validates the UDP length field against the actual length of the datagram.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = UdpReader::new(bytes)?;

        if reader.length() as usize != reader.header_len() + reader.payload().len() {
            return Err("UDP length field is invalid. Does not match actual length.");
        }

        Ok(reader)
    }
}

impl<'a> Parse<'a> for Icmpv4Reader<'a> {
    /// Parses an ICMPv4 message from a byte slice.
    ///
    /// Validates the ICMPv4 type and code fields.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = Icmpv4Reader::new(bytes)?;

        if Icmpv4Type::from(reader.icmp_type()) == Icmpv4Type::Unknown {
            return Err("ICMPv4 type field is invalid.");
        }

        if reader.icmp_code() > ICMPV4_MAX_VALID_CODE {
            return Err("ICMPv4 code field is invalid.");
        }

        Ok(reader)
    }
}

impl<'a> Parse<'a> for Icmpv6Reader<'a> {
    /// Parses an ICMPv6 message from a byte slice.
    ///
    /// Validates the ICMPv6 type field.
    #[inline]
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let reader = Icmpv6Reader::new(bytes)?;

        if Icmpv6Type::from(reader.icmp_type()) == Icmpv6Type::Unknown {
            return Err("ICMPv6 type field is invalid.");
        }

        Ok(reader)
    }
}

/// Trait to verify the checksum of protocols encapsulated in IP packets.
pub trait VerifyChecksum<'a> {
    /// Verifies the checksum of the encapsulated protocol.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure based on the checksum validation.
    fn verify_checksum(&self) -> Result<(), &'static str>;
}

impl<'a> VerifyChecksum<'a> for IPv4Reader<'a> {
    /// Verifies the checksum of an encapsulated protocol in an IPv4 packet.
    ///
    /// Computes the pseudo-header checksum and verifies it with the encapsulated payload.
    #[inline]
    fn verify_checksum(&self) -> Result<(), &'static str> {
        let src: [u8; 4] = self.src_ip().try_into().unwrap(); // Won't panic.
        let dest: [u8; 4] = self.dest_ip().try_into().unwrap(); // Won't panic.
        let protocol = self.protocol();

        let sum = if IpProtocol::from(protocol) == IpProtocol::Icmpv4 {
            0
        } else {
            pseudo_header(&src, &dest, protocol, self.payload().len())
        };

        if !verify_internet_checksum(self.payload(), sum) {
            return Err("Encapsulated checksum is invalid.");
        }

        Ok(())
    }
}

impl<'a> VerifyChecksum<'a> for IPv6Reader<'a> {
    /// Verifies the checksum of an encapsulated protocol in an IPv6 packet.
    ///
    /// Computes the pseudo-header checksum and verifies it with the encapsulated payload.
    #[inline]
    fn verify_checksum(&self) -> Result<(), &'static str> {
        let src: [u8; 16] = self.src_addr().try_into().unwrap(); // Won't panic.
        let dest: [u8; 16] = self.dest_addr().try_into().unwrap(); // Won't panic.

        let sum = pseudo_header(&src, &dest, self.next_header(), self.payload().len());

        if !verify_internet_checksum(self.payload(), sum) {
            return Err("Encapsulated checksum is invalid.");
        }

        Ok(())
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

    #[test]
    fn test_ipv6_udp_payload() {
        // UDP packet (Ethernet + IPv6 + UDP + Payload).
        let packet = [
            0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x11, 0x03, 0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe, 0x05, 0x01,
            0x04, 0x10, 0x00, 0x00, 0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
            0x82, 0xa1, 0x00, 0x14, 0x81, 0x13, 0x07, 0x03, 0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36,
            0xef, 0x5d, 0x0a, 0x00,
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
        assert!(unwrapped.udp.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.icmpv6.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());

        // Unwrap UDP header.
        let udp = unwrapped.udp.unwrap();

        // Ensure payload is correct.
        assert_eq!(
            udp.payload(),
            [0x07, 0x03, 0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xef, 0x5d, 0x0a, 0x00]
        );
    }
}
