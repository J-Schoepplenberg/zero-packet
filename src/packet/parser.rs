use crate::{
    datalink::{
        arp::ArpReader,
        ethernet::{EthernetReader, ETHERNET_MIN_FRAME_LENGTH},
    },
    misc::{EtherType, IcmpType, IpProtocol},
    network::{
        checksum::{pseudo_header, verify_internet_checksum},
        icmp::{IcmpReader, ICMP_MAX_VALID_CODE},
        ipv4::{IPv4Reader, IPV4_MIN_HEADER_LENGTH},
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
    pub tcp: Option<TcpReader<'a>>,
    pub udp: Option<UdpReader<'a>>,
    pub icmp: Option<IcmpReader<'a>>,
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
            tcp: None,
            udp: None,
            icmp: None,
        };

        match EtherType::from(ethertype) {
            EtherType::ARP => parser.parse_arp(&bytes[header_len..])?,
            EtherType::IPv4 => parser.parse_ipv4(&bytes[header_len..])?,
            EtherType::IPv6 => todo!("IPv6 not supported yet."),
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

        let header_len = reader.header_len();
        let protocol = reader.protocol();

        if header_len < IPV4_MIN_HEADER_LENGTH {
            return Err("IPv4 IHL field is invalid. Indicated header length is too short.");
        }

        if bytes.len() < header_len {
            return Err("IPv4 header length is invalid. Indicated header length is too long.");
        }

        self.ipv4 = Some(reader);

        match IpProtocol::from(protocol) {
            IpProtocol::ICMP => self.parse_icmp(&bytes[header_len..])?,
            IpProtocol::TCP => self.parse_tcp(&bytes[header_len..])?,
            IpProtocol::UDP => self.parse_udp(&bytes[header_len..])?,
            IpProtocol::Unknown(_) => return Err("Unknown IPv4 Protocol."),
        }

        Ok(())
    }

    /// Parses a ICMP header.
    #[inline]
    pub fn parse_icmp(&mut self, bytes: &'a [u8]) -> Result<(), &'static str> {
        let reader = IcmpReader::new(bytes)?;

        if IcmpType::from(reader.icmp_type()) == IcmpType::Unknown {
            return Err("ICMP type field is invalid.");
        }

        if reader.icmp_code() > ICMP_MAX_VALID_CODE {
            return Err("ICMP code field is invalid.");
        }

        self.icmp = Some(reader);

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

    /// Verifies the checksums of encapsulated headers.
    #[inline]
    pub fn verify_checksums(&self) -> Result<(), &'static str> {
        let pseudo = self
            .ipv4
            .as_ref()
            .map(|ipv4| {
                if !verify_internet_checksum(ipv4.header(), 0) {
                    return Err("IPv4 checksum is invalid.");
                }
                Ok((ipv4.src_ip(), ipv4.dest_ip(), ipv4.protocol()))
            })
            .transpose()?;

        if let Some(icmp) = &self.icmp {
            if !verify_internet_checksum(icmp.bytes, 0) {
                return Err("ICMP checksum is invalid.");
            }
        }

        if let Some(tcp) = &self.tcp {
            Self::verify_transport_checksum(tcp.bytes, pseudo)?;
        }

        if let Some(udp) = &self.udp {
            Self::verify_transport_checksum(udp.bytes, pseudo)?;
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
        let (src_ip, dest_ip, protocol) =
            pseudo.ok_or("Checksum cannot be verified without a pseudo header.")?;

        let sip = src_ip.try_into().unwrap();
        let dip = dest_ip.try_into().unwrap();

        let pseudo_sum = pseudo_header(sip, dip, protocol, bytes.len());

        if !verify_internet_checksum(bytes, pseudo_sum) {
            return Err(match IpProtocol::from(protocol) {
                IpProtocol::TCP => "TCP checksum is invalid.",
                IpProtocol::UDP => "UDP checksum is invalid.",
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

        if let Some(tcp) = &self.tcp {
            len += tcp.header_len();
        }

        if let Some(udp) = &self.udp {
            len += udp.header_len();
        }

        if let Some(icmp) = &self.icmp {
            len += icmp.header_len();
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
    fn test_parse_valid_packet() {
        // Raw packet data.
        let packet = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 69, 143, 48, 57, 212, 49,
            112, 57, 123, 1, 71, 118, 192, 168, 1, 1, 192, 168, 1, 2, 8, 0, 247, 255, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
        assert!(unwrapped.icmp.is_some());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());
        assert!(unwrapped.udp.is_none());

        // Ensure the header length is correct.
        assert_eq!(unwrapped.header_len(), 42);

        // Verify the checksums.
        assert!(unwrapped.verify_checksums().is_ok());

        // Unwrap the Ethernet header.
        let ethernet = unwrapped.ethernet.unwrap();

        // Ensure there is no VLAN tag.
        assert!(ethernet.vlan_tag().is_none());

        // Ensure there is no double VLAN tag.
        assert!(ethernet.double_vlan_tag().is_none());

        // Unwrap the ICMP header.
        let icmp = unwrapped.icmp.unwrap();

        // Ensure the ICMP type is correct.
        assert_eq!(IcmpType::from(icmp.icmp_type()), IcmpType::EchoRequest);

        // Extract the ICMP payload.
        let payload = icmp.payload();

        // Ensure the payload is correct.
        assert_eq!(
            payload,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
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
        assert!(unwrapped.icmp.is_none());
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
        assert!(unwrapped.icmp.is_none());
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
    fn test_guess_icmp_echo_response() {
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
        assert!(unwrapped.icmp.is_some());
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.tcp.is_none());
        assert!(unwrapped.udp.is_none());

        // Unwrap headers.
        let ethernet = unwrapped.ethernet.unwrap();
        let ipv4 = unwrapped.ipv4.unwrap();
        let icmp = unwrapped.icmp.unwrap();

        // Ensure the fields are correct.
        assert_eq!(ethernet.ethertype(), 0x0800);
        assert_eq!(ipv4.protocol(), 1);
        assert_eq!(ipv4.checksum(), 0xfa30);
        assert_eq!(icmp.icmp_type(), 0);
        assert_eq!(icmp.icmp_code(), 0);
        assert_eq!(icmp.checksum(), 0x45da);
    }
}
