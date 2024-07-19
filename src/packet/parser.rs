use crate::{
    datalink::{
        arp::ArpReader,
        ethernet::{EthernetReader, ETHERNET_MIN_FRAME_LENGTH},
    },
    misc::{EtherType, Icmpv4Type, Icmpv6Type, IpInIp, IpProtocol},
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
    pub ip_in_ip: Option<IpInIp<'a>>,
    pub tcp: Option<TcpReader<'a>>,
    pub udp: Option<UdpReader<'a>>,
    pub icmpv4: Option<Icmpv4Reader<'a>>,
    pub icmpv6: Option<Icmpv6Reader<'a>>,
}

impl<'a> PacketParser<'a> {
    /// Creates a new `PacketParser`.
    #[inline]
    fn new() -> Self {
        Self {
            ethernet: None,
            arp: None,
            ipv4: None,
            ipv6: None,
            ip_in_ip: None,
            tcp: None,
            udp: None,
            icmpv4: None,
            icmpv6: None,
        }
    }

    /// Determines the protocols encapsulated in some bytes and attempts to parse them.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let ethernet = EthernetReader::parse(bytes)?;
        let payload = &bytes[ethernet.header_len()..];

        let mut parser = PacketParser::new();

        match EtherType::from(ethernet.ethertype()) {
            EtherType::Arp => parser.arp = Some(ArpReader::parse(payload)?),
            EtherType::Ipv4 => parser.ipv4(payload, true)?,
            EtherType::Ipv6 => parser.ipv6(payload, true)?,
            _ => (), // Unknown EtherType, proceed.
        }

        parser.ethernet = Some(ethernet);

        Ok(parser)
    }

    /// Parsing IPv4 packets.
    #[inline]
    fn ipv4(&mut self, payload: &'a [u8], from_ether: bool) -> Result<(), &'static str> {
        let ipv4 = IPv4Reader::parse(payload)?;

        let payload = ipv4.payload()?;
        let protocol = IpProtocol::from(ipv4.protocol());

        self.parse_protocol(protocol, payload, &ipv4)?;

        if from_ether {
            self.ipv4 = Some(ipv4);
        } else {
            self.ip_in_ip = Some(IpInIp::Ipv4(ipv4));
        }

        Ok(())
    }

    /// Parsing IPv6 packets.
    #[inline]
    fn ipv6(&mut self, payload: &'a [u8], from_ether: bool) -> Result<(), &'static str> {
        let ipv6 = IPv6Reader::parse(payload)?;

        let payload = ipv6.upper_layer_payload();
        let next_header = IpProtocol::from(ipv6.final_next_header());

        self.parse_protocol(next_header, payload, &ipv6)?;

        if from_ether {
            self.ipv6 = Some(ipv6);
        } else {
            self.ip_in_ip = Some(IpInIp::Ipv6(ipv6));
        }

        Ok(())
    }

    /// Parsing encapsulated protocols.
    #[inline]
    fn parse_protocol<T: IpReader<'a>>(
        &mut self,
        protocol: IpProtocol,
        payload: &'a [u8],
        reader: &T,
    ) -> Result<(), &'static str> {
        match protocol {
            IpProtocol::Tcp => {
                self.tcp = Some(TcpReader::parse(payload)?);
                reader.verify_checksum()?;
            }
            IpProtocol::Udp => {
                self.udp = Some(UdpReader::parse(payload)?);
                reader.verify_checksum()?;
            }
            IpProtocol::Icmpv4 => {
                self.icmpv4 = Some(Icmpv4Reader::parse(payload)?);
                reader.verify_checksum()?;
            }
            IpProtocol::Icmpv6 => {
                self.icmpv6 = Some(Icmpv6Reader::parse(payload)?);
                reader.verify_checksum()?;
            }
            IpProtocol::Ipv4 => self.ipv4(payload, false)?,
            IpProtocol::Ipv6 => self.ipv6(payload, false)?,
            _ => (), // Unknown protocol, proceed.
        }

        Ok(())
    }
}

/// Trait to parse a protocol header.
pub trait Parse<'a>: Sized {
    /// Parses the protocol header from the given slice.
    ///
    /// Checks certain fields for validity.
    ///
    /// May fail if any of the fields are deemed invalid.
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

        if reader.header_len() < IPV4_MIN_HEADER_LENGTH {
            return Err("IPv4 IHL field is invalid. Indicated header length is too short.");
        }

        if bytes.len() < reader.header_len() {
            return Err("IPv4 header length is invalid. Indicated header length is too long.");
        }

        if bytes.len() != reader.total_length() as usize {
            return Err("IPv4 total length field is invalid. Does not match actual length.");
        }

        if !reader.valid_checksum()? {
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
pub trait IpReader<'a> {
    /// Verifies the checksum of the encapsulated protocol.
    fn verify_checksum(&self) -> Result<(), &'static str>;
}

impl<'a> IpReader<'a> for IPv4Reader<'a> {
    /// Verifies the checksum of an encapsulated protocol in an IPv4 packet.
    ///
    /// Computes the pseudo-header checksum and verifies it with the encapsulated payload.
    #[inline]
    fn verify_checksum(&self) -> Result<(), &'static str> {
        let src: [u8; 4] = self.src_ip().try_into().unwrap(); // Won't panic.
        let dest: [u8; 4] = self.dest_ip().try_into().unwrap(); // Won't panic.
        let protocol = self.protocol();

        // ICMPv4 does not use a pseudo-header for checksum calculation.
        let sum = if IpProtocol::from(protocol) == IpProtocol::Icmpv4 {
            0
        } else {
            pseudo_header(&src, &dest, protocol, self.payload()?.len())
        };

        if !verify_internet_checksum(self.payload()?, sum) {
            return Err("IPv4 encapsulated checksum is invalid.");
        }

        Ok(())
    }
}

impl<'a> IpReader<'a> for IPv6Reader<'a> {
    /// Verifies the checksum of an encapsulated protocol in an IPv6 packet.
    ///
    /// Computes the pseudo-header checksum and verifies it with the encapsulated payload.
    #[inline]
    fn verify_checksum(&self) -> Result<(), &'static str> {
        if IpProtocol::from(self.final_next_header()) == IpProtocol::NoNextHeader {
            return Ok(());
        }

        let src: [u8; 16] = self.src_addr().try_into().unwrap(); // Won't panic.
        let dest: [u8; 16] = self.dest_addr().try_into().unwrap(); // Won't panic.

        let sum = pseudo_header(
            &src,
            &dest,
            self.final_next_header(),
            self.upper_layer_payload().len(),
        );

        if !verify_internet_checksum(self.upper_layer_payload(), sum) {
            return Err("IPv6 encapsulated checksum is invalid.");
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
        assert!(parser.is_err());
    }

    #[test]
    fn test_vlan_tagged_frame() {
        // Ethernet II + IPv4 (VLAN tagged) + UDP.
        let packet = [
            // Ethernet header.
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Destination MAC.
            0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x00, // Source MAC.
            0x81, 0x00, // VLAN Ethertype.
            0x00, 0x64, // VLAN Tag (priority 0, CFI 0, VLAN ID 100).
            0x08, 0x00, // Ethertype (IPv4).
            // IPv4 header.
            0x45, 0x00, 0x00, 0x2e, // Version, IHL, DSCP, ECN, Total Length (46 bytes).
            0x00, 0x00, 0x00, 0x00, // Identification, Flags, Fragment Offset.
            0x40, 0x11, 0xf9, 0x6b, // TTL (64), Protocol (UDP), IPv4 Checksum.
            0xC0, 0xA8, 0x00, 0x01, // Source IP (192.168.0.1).
            0xC0, 0xA8, 0x00, 0x02, // Destination IP (192.168.0.2).
            // UDP header.
            0x04, 0xD2, 0x16, 0x2E, // Source Port (1234), Destination Port (5678).
            0x00, 0x1a, 0x63, 0x66, // Length (26 bytes), UDP Checksum.
            // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, // Padding.
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
        // Ethernet II + IPv4 (double VLAN tagged) + UDP.
        let packet = [
            // Ethernet header.
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Destination MAC.
            0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x00, // Source MAC.
            0x88, 0xA8, // Outer VLAN Ethertype.
            0x00, 0xC8, // Outer VLAN Tag (priority 0, CFI 0, VLAN ID 200).
            0x81, 0x00, // Inner VLAN Ethertype.
            0x00, 0x64, // Inner VLAN Tag (priority 0, CFI 0, VLAN ID 100).
            0x08, 0x00, // Ethertype (IPv4).
            // IPv4 header.
            0x45, 0x00, 0x00, 0x2a, // Version, IHL, DSCP, ECN, Total Length (42 bytes).
            0x00, 0x00, 0x00, 0x00, // Identification, Flags, Fragment Offset.
            0x40, 0x11, 0xf9, 0x6f, // TTL (64), Protocol (UDP), IPv4 Checksum.
            0xC0, 0xA8, 0x00, 0x01, // Source IP (192.168.0.1).
            0xC0, 0xA8, 0x00, 0x02, // Destination IP (192.168.0.2).
            // UDP header.
            0x04, 0xD2, 0x16, 0x2E, // Source Port (1234), Destination Port (5678).
            0x00, 0x16, 0x63, 0x6e, // Length (22 bytes), UDP Checksum (0x6366).
            // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, 0x00, 0x00, // Padding.
            0x00, 0x00, // Padding.
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
        // Ethernet II + IPv4 + ICMP.
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
        // Ethernet II + IPv6 + ICMPv6.
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
        // Ethernet II + IPv6 + UDP + Payload.
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

    #[test]
    fn test_ipv6_routing_extension_header() {
        // Ethernet II + IPv6 + Routing extension header + TCP.
        let packet = [
            0x86, 0x93, 0x23, 0xd3, 0x37, 0x8e, 0x22, 0x1a, 0x95, 0xd6, 0x7a, 0x23, 0x86, 0xdd,
            0x60, 0x0f, 0xbb, 0x74, 0x00, 0x88, 0x2b, 0x3f, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x06,
            0x04, 0x02, 0x02, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1f, 0x90,
            0xa9, 0xa0, 0xba, 0x31, 0x1e, 0x8d, 0x02, 0x1b, 0x63, 0x8d, 0xa0, 0x12, 0x70, 0xf8,
            0x8a, 0xf5, 0x00, 0x00, 0x02, 0x04, 0x07, 0x94, 0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d,
            0xa5, 0x22, 0x80, 0x1d, 0xa5, 0x22, 0x01, 0x03, 0x03, 0x07,
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
        assert!(unwrapped.tcp.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.icmpv6.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.udp.is_none());

        // Unwrap IPv6 header.
        let ipv6 = unwrapped.ipv6.unwrap();

        // Ensure extension headers are present.
        assert!(ipv6.extension_headers.is_some());

        // Unwrap extension headers.
        let extension_headers = ipv6.extension_headers.unwrap();

        // Ensure routing extension header is present.
        assert!(extension_headers.routing.is_some());
    }

    #[test]
    fn test_ipv6_hop_by_hop_options() {
        // Ethernet II + IPv6 + Hop-by-Hop Options + TCP.
        let packet = [
            0x44, 0x2a, 0x60, 0xf6, 0x27, 0x8a, 0x00, 0x0c, 0x29, 0x30, 0x76, 0xb5, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x04, 0x00, 0x1c, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x0c, 0x00, 0x87, 0x00, 0x00, 0x52, 0x0c,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x40, 0x38, 0xcb, 0x04, 0x00, 0x00,
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
        assert!(unwrapped.tcp.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.icmpv6.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.udp.is_none());

        // Unwrap IPv6 header.
        let ipv6 = unwrapped.ipv6.unwrap();

        // Ensure extension headers are present.
        assert!(ipv6.extension_headers.is_some());

        // Unwrap extension headers.
        let extension_headers = ipv6.extension_headers.unwrap();

        // Ensure hop-by-hop options extension header is present.
        assert!(extension_headers.hop_by_hop.is_some());
    }

    #[test]
    fn test_ipv6_destination_options() {
        // Ethernet II + IPv6 + Destination Options + TCP.
        let packet = [
            0x44, 0x2a, 0x60, 0xf6, 0x27, 0x8a, 0x00, 0x0c, 0x29, 0x30, 0x76, 0xb5, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x05, 0x00, 0x1c, 0x3c, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x0d, 0x00, 0x87, 0x00, 0x00, 0x52, 0x0d,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x40, 0x38, 0xcb, 0x02, 0x00, 0x00,
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
        assert!(unwrapped.tcp.is_some());

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.icmpv6.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.udp.is_none());

        // Unwrap IPv6 header.
        let ipv6 = unwrapped.ipv6.unwrap();

        // Ensure extension headers are present.
        assert!(ipv6.extension_headers.is_some());

        // Unwrap extension headers.
        let extension_headers = ipv6.extension_headers.unwrap();

        // Ensure hop-by-hop options extension header is present.
        assert!(extension_headers.destination_1st.is_some());
    }

    #[test]
    fn test_fragment_and_authentication_header() {
        // IPv6 with fragment extension header and ICMPv6.
        let pkt1 = [
            0x70, 0x77, 0x81, 0xdd, 0xc3, 0x7c, 0x00, 0x26, 0x9e, 0x71, 0x9d, 0x33, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x98, 0x2c, 0x9c, 0x26, 0x05, 0x60, 0x00, 0x23, 0xc0,
            0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x20, 0x01, 0x41, 0xd0,
            0x00, 0x08, 0xcc, 0xd8, 0x01, 0x37, 0x00, 0x74, 0x01, 0x87, 0x01, 0x01, 0x3a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x80, 0x00, 0x0b, 0xaf, 0x15, 0x5e, 0x3a, 0xfb,
            0x4c, 0x9a, 0x02, 0x5c, 0x81, 0x31, 0xcf, 0xf7, 0x5c, 0xed, 0x0c, 0x57, 0x8a, 0xd0,
            0x7d, 0x40, 0x11, 0x01, 0x08, 0x3a, 0x61, 0x57, 0xea, 0x73, 0xc4, 0xa1, 0x8a, 0x2e,
            0x23, 0x3b, 0xdc, 0x78, 0x80, 0xa1, 0x25, 0x54, 0xe3, 0x12, 0x90, 0x48, 0xa6, 0x02,
            0xff, 0x3b, 0x2f, 0xd4, 0x0a, 0x7a, 0x86, 0xf2, 0x81, 0x2d, 0x36, 0x16, 0x9e, 0x20,
            0x34, 0xf5, 0x0d, 0x63, 0xef, 0xc7, 0xd5, 0x2a, 0x8f, 0x43, 0x6c, 0x64, 0xb7, 0x69,
            0x0f, 0x6f, 0x86, 0xca, 0x55, 0x57, 0xd7, 0x71, 0x68, 0x1e, 0xac, 0x9c, 0x68, 0x6f,
            0x93, 0x89, 0xe9, 0x1d, 0x34, 0xbe, 0xdc, 0x50, 0x19, 0x6d, 0x00, 0x53, 0x2d, 0x6a,
            0xcb, 0x4a, 0x57, 0x61, 0xcf, 0x63, 0x99, 0x19, 0x42, 0x45, 0x46, 0xc7, 0x30, 0x57,
            0x95, 0x1d, 0x67, 0x55, 0x0a, 0xa7, 0xb0, 0x00, 0x4a, 0xc1, 0x42, 0x43, 0x0e, 0xe4,
            0x2e, 0x51, 0x05, 0xe2, 0x8c, 0x42, 0xa7, 0xae, 0x4f, 0x1a,
        ];

        // Parse the packet.
        let prs1 = PacketParser::parse(&pkt1);

        // Ensure the parser succeeds.
        assert!(prs1.is_ok());

        // IPv6 with Authentication Header (AH) extension header.
        let pkt2 = [
            0x00, 0x1e, 0x7a, 0x79, 0x3f, 0x10, 0x00, 0x15, 0x62, 0x6a, 0xfe, 0xf1, 0x86, 0xdd,
            0x6e, 0x00, 0x00, 0x00, 0x00, 0x44, 0x33, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x15, 0x62, 0xff, 0xfe, 0x6a, 0xfe, 0xf1, 0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x1e, 0x7a, 0xff, 0xfe, 0x79, 0x3f, 0x10, 0x59, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x09, 0x07, 0x00, 0x00, 0x00, 0xff, 0xd1, 0x54, 0xcc, 0xe6,
            0x68, 0xcb, 0xcf, 0xfa, 0xfe, 0xbb, 0x93, 0xb8, 0x03, 0x01, 0x00, 0x2c, 0xc0, 0xa8,
            0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x22, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x01, 0x00, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x28, 0xc0, 0xa8, 0xff, 0x0f, 0xc0, 0xa8,
            0xff, 0x0e, 0xc0, 0xa8, 0xff, 0x0b, 0xc0, 0xa8, 0xff, 0x0f, 0x7f, 0xf4, 0xe0, 0xb7,
        ];

        // Parse the packet.
        let prs2 = PacketParser::parse(&pkt2);

        // Ensure the parser succeeds.
        assert!(prs2.is_ok());
    }

    #[test]
    fn test_extension_headers_chained() {
        // IPv6 with extension headers chained together.
        // Ethernet II + IPv6 + Hop-by-Hop + Destination + NoNextHeader.
        let packet = [
            // Ethernet II.
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Destination MAC Address.
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5F, // Source MAC Address.
            0x86, 0xDD, // Type: IPv6 (0x86DD).
            // IPv6 Header.
            0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label.
            0x00, 0x20, // Payload Length (32 bytes).
            0x00, // Next Header: Hop-by-Hop Options (0x00).
            0x40, // Hop Limit.
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, // Source Address.
            0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x34, // Source Address.
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination Address.
            0x02, 0x02, 0xB3, 0xFF, 0xFE, 0x1E, 0x83, 0x29, // Destination Address.
            // Hop-by-Hop Options Header.
            0x3C, // Next Header: Destination Options (0x3C).
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Options and padding.
            // Destination Options Header.
            0x3B, // Next Header: No Next Header (0x3B).
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Options and padding.
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

        // Ensure these headers are not present.
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.icmpv6.is_none());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.udp.is_none());
        assert!(unwrapped.tcp.is_none());

        // Unwrap IPv6 header.
        let ipv6 = unwrapped.ipv6.unwrap();

        // Ensure extension headers are present.
        assert!(ipv6.extension_headers.is_some());

        // Unwrap extension headers.
        let extension_headers = ipv6.extension_headers.unwrap();

        // Ensure hop-by-hop options extension header is present.
        assert!(extension_headers.hop_by_hop.is_some());

        // Ensure destination options extension header is present.
        assert!(extension_headers.destination_1st.is_some());
    }

    #[test]
    pub fn test_ipv6_in_ipv6_with_extension_header() {
        // Ethernet II + IPv6 + Routing Header (Segment Routing) + IPv6 + TCP.
        let packet = [
            0x86, 0x93, 0x23, 0xd3, 0x37, 0x8e, 0x22, 0x1a, 0x95, 0xd6, 0x7a, 0x23, 0x86, 0xdd,
            0x60, 0x0f, 0xbb, 0x74, 0x00, 0x88, 0x2b, 0x3f, 0xfc, 0x00, 0x00, 0x42, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfc, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x29, 0x06,
            0x04, 0x02, 0x02, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x60, 0x0f,
            0xbb, 0x74, 0x00, 0x28, 0x06, 0x40, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfc, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1f, 0x90, 0xa9, 0xa0,
            0xba, 0x31, 0x1e, 0x8d, 0x02, 0x1b, 0x63, 0x8d, 0xa0, 0x12, 0x70, 0xf8, 0x8a, 0xf5,
            0x00, 0x00, 0x02, 0x04, 0x07, 0x94, 0x04, 0x02, 0x08, 0x0a, 0x80, 0x1d, 0xa5, 0x22,
            0x80, 0x1d, 0xa5, 0x22, 0x01, 0x03, 0x03, 0x07,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());
    }

    #[test]
    pub fn test_ipv6_in_ipv4() {
        // Ethernet II + IPv4 + IPv6 + ICMPv6.
        let packet = [
            0xc2, 0x01, 0x42, 0x02, 0x00, 0x00, 0xc2, 0x00, 0x42, 0x02, 0x00, 0x00, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x78, 0x00, 0x09, 0x00, 0x00, 0xff, 0x29, 0xa7, 0x51, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x3a, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x80, 0x00, 0x7e, 0x8f, 0x18, 0xdc, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());
    }

    #[test]
    fn test_ipv4_in_ipv4() {
        // Ethernet II + IPv4 + IPv4 + ICMP.
        let packet = [
            0xc2, 0x01, 0x57, 0x75, 0x00, 0x00, 0xc2, 0x00, 0x57, 0x75, 0x00, 0x00, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x78, 0x00, 0x14, 0x00, 0x00, 0xff, 0x04, 0xa7, 0x6b, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x45, 0x00, 0x00, 0x64, 0x00, 0x14, 0x00, 0x00,
            0xff, 0x01, 0xb5, 0x7f, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x08, 0x00,
            0x43, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x3b, 0x38,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(parser.is_ok());
    }
}
