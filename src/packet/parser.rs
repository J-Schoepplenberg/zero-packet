use crate::{
    datalink::{
        arp::ArpParser,
        ethernet::{EthernetParser, ETHERNET_MIN_FRAME_LENGTH},
    },
    misc::{EtherType, IcmpType, IpProtocol},
    network::{
        checksum::verify_internet_checksum,
        icmp::{IcmpParser, ICMP_MAX_VALID_CODE},
        ipv4::{IPv4Parser, IPV4_MIN_HEADER_LENGTH},
    },
    transport::{
        tcp::{TcpParser, TCP_MIN_HEADER_LENGTH},
        udp::UdpParser,
    },
};

/// A zero-copy packet parser.
#[derive(Debug)]
pub struct PacketParser<'a> {
    pub ethernet: Option<EthernetParser<'a>>,
    pub arp: Option<ArpParser<'a>>,
    pub ipv4: Option<IPv4Parser<'a>>,
    pub tcp: Option<TcpParser<'a>>,
    pub udp: Option<UdpParser<'a>>,
    pub icmp: Option<IcmpParser<'a>>,
}

impl<'a> PacketParser<'a> {
    /// Parses a raw Ethernet frame.
    ///
    /// Is strict about what input it accepts.
    pub fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.len() < ETHERNET_MIN_FRAME_LENGTH {
            return Err("Slice needs to be least 64 bytes long to be a valid Ethernet frame.");
        }

        let ethernet_parser = EthernetParser::new(packet)?;
        let header_len = ethernet_parser.header_length();
        let ethertype = ethernet_parser.get_ethertype();

        let mut parser = PacketParser {
            arp: None,
            ethernet: Some(ethernet_parser),
            ipv4: None,
            tcp: None,
            udp: None,
            icmp: None,
        };

        match EtherType::from(ethertype) {
            EtherType::ARP => parser.parse_arp(&packet[header_len..])?,
            EtherType::IPv4 => parser.parse_ipv4(&packet[header_len..])?,
            EtherType::IPv6 => todo!("IPv6 not supported yet."),
            EtherType::Unknown(_) => return Err("Unknown or unsupported EtherType"),
        }

        parser.verify_checksums()?;

        Ok(parser)
    }

    /// Parses a ARP header.
    ///
    /// ARP was originally designed for Ethernet, IPv4 and MAC addresses.
    ///
    /// Theoretically, it can also be used with other combinations of protocols.
    #[inline]
    pub fn parse_arp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let arp_parser = ArpParser::new(data)?;

        if arp_parser.get_oper() > 2 {
            return Err("ARP oper field is invalid, expected request (1) or reply (2).");
        }

        self.arp = Some(arp_parser);

        Ok(())
    }

    /// Parses a IPv4 header.
    #[inline]
    pub fn parse_ipv4(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let ipv4_parser = IPv4Parser::new(data)?;

        if ipv4_parser.get_version() != 4 {
            return Err("IPv4 version field is invalid. Expected version 4.");
        }

        let header_len = ipv4_parser.header_length();
        let protocol = ipv4_parser.get_protocol();

        if header_len < IPV4_MIN_HEADER_LENGTH {
            return Err("IPv4 IHL field is invalid. Indicated header length is too short.");
        }

        self.ipv4 = Some(ipv4_parser);

        match IpProtocol::from(protocol) {
            IpProtocol::ICMP => self.parse_icmp(&data[header_len..])?,
            IpProtocol::TCP => self.parse_tcp(&data[header_len..])?,
            IpProtocol::UDP => self.parse_udp(&data[header_len..])?,
            IpProtocol::Unknown(_) => return Err("Unknown IPv4 Protocol."),
        }

        Ok(())
    }

    /// Parses a ICMP packet.
    #[inline]
    pub fn parse_icmp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let icmp_parser = IcmpParser::new(data)?;

        if IcmpType::from(icmp_parser.get_type()) == IcmpType::Unknown {
            return Err("ICMP type field is invalid.");
        }

        if icmp_parser.get_code() > ICMP_MAX_VALID_CODE {
            return Err("ICMP code field is invalid.");
        }

        self.icmp = Some(icmp_parser);

        Ok(())
    }

    /// Parses a TCP header.
    #[inline]
    pub fn parse_tcp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let tcp_parser = TcpParser::new(data)?;

        if tcp_parser.header_length() < TCP_MIN_HEADER_LENGTH {
            return Err("TCP data offset field is invalid. Indicated header length is too short.");
        }

        if tcp_parser.get_flags() == 0 {
            return Err("TCP flags field is invalid.");
        }

        self.tcp = Some(tcp_parser);

        Ok(())
    }

    /// Parses a UDP header.
    #[inline]
    pub fn parse_udp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let udp_parser = UdpParser::new(data)?;

        let header_len = udp_parser.header_length();
        let payload_len = udp_parser.get_payload().len();
        let length_field = udp_parser.get_length() as usize;

        if length_field != header_len + payload_len {
            return Err("UDP length field is invalid. Does not match actual length.");
        }

        self.udp = Some(udp_parser);

        Ok(())
    }

    /// Verifies the checksums of the headers.
    #[inline]
    pub fn verify_checksums(&self) -> Result<(), &'static str> {
        if let Some(ipv4) = &self.ipv4 {
            if !verify_internet_checksum(ipv4.get_header()) {
                return Err("IPv4 checksum is invalid.");
            }
        }

        if let Some(icmp) = &self.icmp {
            if !verify_internet_checksum(icmp.data) {
                return Err("ICMP checksum is invalid.");
            }
        }

        if let Some(tcp) = &self.tcp {
            if !verify_internet_checksum(tcp.data) {
                return Err("TCP checksum is invalid.");
            }
        }

        if let Some(udp) = &self.udp {
            if !verify_internet_checksum(udp.data) {
                return Err("UDP checksum is invalid.");
            }
        }

        Ok(())
    }

    /// Returns the total length of all headers.
    #[inline]
    pub fn header_len(&self) -> usize {
        let mut len = 0;

        if let Some(ethernet) = &self.ethernet {
            len += ethernet.header_length();
        }

        if let Some(arp) = &self.arp {
            len += arp.header_length();
        }

        if let Some(ipv4) = &self.ipv4 {
            len += ipv4.header_length();
        }

        if let Some(tcp) = &self.tcp {
            len += tcp.header_length();
        }

        if let Some(udp) = &self.udp {
            len += udp.header_length();
        }

        if let Some(icmp) = &self.icmp {
            len += icmp.header_length();
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

        // Get the total length of all headers.
        let header_len = unwrapped.header_len();

        // Ensure the header length is correct.
        assert_eq!(header_len, 42);

        // Verify the checksums.
        assert!(unwrapped.verify_checksums().is_ok());

        // Unwrap the ICMP header.
        let icmp = unwrapped.icmp.unwrap();

        // Ensure the ICMP type is correct.
        assert_eq!(IcmpType::from(icmp.get_type()), IcmpType::EchoRequest);

        // Extract the ICMP payload.
        let payload = icmp.get_payload();

        // Ensure the payload is correct.
        assert_eq!(
            payload,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
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
        let packet_parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert!(packet_parser.is_ok());

        // Unwrap the parser.
        let unwrapped = packet_parser.unwrap();

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
        assert_eq!(ethernet.get_ethertype(), 0x0800);
        assert_eq!(ipv4.get_protocol(), 1);
        assert_eq!(ipv4.get_checksum(), 0xfa30);
        assert_eq!(icmp.get_type(), 0);
        assert_eq!(icmp.get_code(), 0);
        assert_eq!(icmp.get_checksum(), 0x45da);
    }
}
