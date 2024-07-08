use crate::{
    datalink::{
        arp::ArpParser,
        ethernet::{EthernetParser, ETHERNET_MIN_FRAME_LENGTH},
    },
    misc::{EtherType, IpProtocol},
    network::{
        icmp::IcmpParser,
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
    pub arp: Option<ArpParser<'a>>,
    pub ethernet: Option<EthernetParser<'a>>,
    pub ipv4: Option<IPv4Parser<'a>>,
    pub tcp: Option<TcpParser<'a>>,
    pub udp: Option<UdpParser<'a>>,
    pub icmp: Option<IcmpParser<'a>>,
}

impl<'a> PacketParser<'a> {
    /// Parses a raw Ethernet frame.
    ///
    /// Is strict about what input it accepts.
    ///
    /// # Arguments
    ///
    /// * `packet` - A byte slice.
    ///
    /// # Returns
    ///
    /// A `PacketParser` instance.
    ///
    /// # Errors
    ///
    /// - Slice too short to contain a whole Ethernet frame.
    /// - Slice too short to contain protocol headers.
    /// - Unknown or unsupported fields.
    /// - Invalid field values.
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

        Ok(parser)
    }

    #[inline]
    pub fn parse_arp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let arp_parser = ArpParser::new(data)?;
        self.arp = Some(arp_parser);
        Ok(())
    }

    #[inline]
    pub fn parse_ipv4(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let ipv4_parser = IPv4Parser::new(data)?;
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

    #[inline]
    pub fn parse_icmp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let icmp_parser = IcmpParser::new(data)?;
        self.icmp = Some(icmp_parser);
        Ok(())
    }

    #[inline]
    pub fn parse_tcp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let tcp_parser = TcpParser::new(data)?;

        if tcp_parser.header_length() < TCP_MIN_HEADER_LENGTH {
            return Err("TCP Data Offset field is invalid. Indicated header length is too short.");
        }

        self.tcp = Some(tcp_parser);

        Ok(())
    }

    #[inline]
    pub fn parse_udp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let udp_parser = UdpParser::new(data)?;
        self.udp = Some(udp_parser);
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
    use crate::network::checksum::verify_internet_checksum;

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
    fn test_ensure_no_allocations() {}

    #[test]
    fn test_parse_valid_packet() {
        // Raw packet data.
        let packet = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 1, 87, 118, 192, 168, 1, 1, 192, 168, 1, 2, 8, 0, 247, 255, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeds.
        assert_eq!(parser.is_ok(), true);

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the parser has the expected fields.
        assert_eq!(unwrapped.ethernet.is_some(), true);
        assert_eq!(unwrapped.ipv4.is_some(), true);
        assert_eq!(unwrapped.icmp.is_some(), true);
        assert_eq!(unwrapped.arp.is_none(), true);
        assert_eq!(unwrapped.tcp.is_none(), true);
        assert_eq!(unwrapped.udp.is_none(), true);

        // Get the total length of all headers.
        let header_len = unwrapped.header_len();

        // Ensure the header length is correct.
        assert_eq!(header_len, 42);

        let ipv4 = unwrapped.ipv4.unwrap();
        let icmp = unwrapped.icmp.unwrap();

        // Get the IPv4 header and ICMP packet.
        let ipv4_header = ipv4.get_header();
        let icmp_packet = icmp.data;

        // Verify the checksums.
        let verify_ipv4 = verify_internet_checksum(ipv4_header);
        let verify_icmp = verify_internet_checksum(icmp_packet);

        // Ensure the checksums are valid.
        assert_eq!(verify_ipv4, true);
        assert_eq!(verify_icmp, true);

        // Extract the ICMP payload.
        let payload = icmp.get_payload();

        // Ensure the payload is correct.
        assert_eq!(
            payload,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
