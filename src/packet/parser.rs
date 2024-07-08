use crate::{
    datalink::{
        arp::ArpParser,
        ethernet::{EthernetParser, ETHERNET_MIN_FRAME_LENGTH},
    },
    network::{
        icmp::IcmpParser,
        ipv4::{IPv4Parser, IPV4_MIN_HEADER_LENGTH},
    },
    transport::{
        tcp::{TcpParser, TCP_MIN_HEADER_LENGTH},
        udp::UdpParser,
    },
    utils::{EtherType, IpProtocol},
};

/// A zero-allocation packet parser.
#[derive(Debug)]
pub struct PacketParser<'a> {
    pub arp: Option<ArpParser<'a>>,
    pub ethernet: Option<EthernetParser<'a>>,
    pub ipv4: Option<IPv4Parser<'a>>,
    pub tcp: Option<TcpParser<'a>>,
    pub udp: Option<UdpParser<'a>>,
    pub icmp: Option<IcmpParser<'a>>,
    pub header_len: usize,
    pub payload: &'a [u8],
}

impl<'a> PacketParser<'a> {
    /// Parses a raw Ethernet frame.
    ///
    /// Is quite strict about what input it accepts.
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
            header_len,
            payload: &[],
        };

        match EtherType::from(ethertype) {
            EtherType::ARP => parser.parse_arp(&packet[header_len..])?,
            EtherType::IPv4 => parser.parse_ipv4(&packet[header_len..])?,
            EtherType::IPv6 => todo!("IPv6 not supported yet."),
            EtherType::Unknown(_) => return Err("Unknown or unsupported EtherType"),
        }

        parser.payload = &packet[header_len..];

        Ok(parser)
    }

    #[inline]
    pub fn parse_arp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let arp_parser = ArpParser::new(data)?;
        self.header_len += arp_parser.header_length();
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

        self.header_len += header_len;
        self.ipv4 = Some(ipv4_parser);

        match IpProtocol::from(protocol) {
            IpProtocol::ICMP => self.parse_icmp(data)?,
            IpProtocol::TCP => self.parse_tcp(data)?,
            IpProtocol::UDP => self.parse_udp(data)?,
            IpProtocol::Unknown(_) => return Err("Unknown IPv4 Protocol."),
        }

        Ok(())
    }

    #[inline]
    pub fn parse_icmp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let icmp_parser = IcmpParser::new(data)?;
        self.header_len += icmp_parser.header_length();
        self.icmp = Some(icmp_parser);
        Ok(())
    }

    #[inline]
    pub fn parse_tcp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let tcp_parser = TcpParser::new(data)?;
        let header_len = tcp_parser.header_length();

        if header_len < TCP_MIN_HEADER_LENGTH {
            return Err("TCP Data Offset field is invalid. Indicated header length is too short.");
        }

        self.header_len += header_len;
        self.tcp = Some(tcp_parser);
        Ok(())
    }

    #[inline]
    pub fn parse_udp(&mut self, data: &'a [u8]) -> Result<(), &'static str> {
        let udp_parser = UdpParser::new(data)?;
        self.header_len += udp_parser.header_length();
        self.udp = Some(udp_parser);
        Ok(())
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
    fn test_parse_icmp() {
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

        // Get the IPv4 header and ICMP packet.
        let ipv4_header = unwrapped.ipv4.unwrap().get_header();
        let icmp_packet = unwrapped.icmp.unwrap().data;

        // Verify the checksums.
        let verify_ipv4 = verify_internet_checksum(ipv4_header);
        let verify_icmp = verify_internet_checksum(icmp_packet);

        // Ensure the checksums are valid.
        assert_eq!(verify_ipv4, true);
        assert_eq!(verify_icmp, true);
    }
}
