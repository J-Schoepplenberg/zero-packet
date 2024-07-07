use crate::{
    datalink::ethernet::EthernetFrame,
    network::ipv4::IPv4Packet,
    transport::{tcp::TcpSegment, udp::UdpDatagram},
};

pub struct PacketBuilder<'a> {
    pub data: &'a mut [u8],
    pos: usize,
}

impl<'a> PacketBuilder<'a> {
    /// Creates a new `PacketBuilder` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> PacketBuilder<'a> {
        PacketBuilder { data, pos: 0 }
    }

    #[inline]
    /// Returns the length of all encapsulated headers in bytes.
    pub fn total_header_length(&self) -> usize {
        self.pos
    }

    /// Sets the Ethernet header fields.
    #[inline]
    pub fn ethernet(
        &mut self,
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        ethertype: u16,
    ) -> Result<&mut Self, &'static str> {
        let mut ethernet_frame = EthernetFrame::new(self.data)?;

        ethernet_frame.set_src_mac(src_mac);
        ethernet_frame.set_dest_mac(dest_mac);
        ethernet_frame.set_ethertype(ethertype);

        self.pos = EthernetFrame::HEADER_LENGTH;

        Ok(self)
    }

    /// Sets the IPv4 header fields.
    #[inline]
    pub fn ipv4(
        &mut self,
        version: u8,
        ihl: u8,
        dscp: u8,
        ecn: u8,
        total_length: u16,
        identification: u16,
        flags: u8,
        fragment_offset: u16,
        ttl: u8,
        protocol: u8,
        src_ip: &[u8; 4],
        dest_ip: &[u8; 4],
    ) -> Result<&mut Self, &'static str> {
        if self.data.len() < self.pos {
            return Err("Data too short to contain an IPv4 header.");
        }

        let mut ipv4_packet = IPv4Packet::new(&mut self.data[self.pos..])?;

        ipv4_packet.set_version(version);
        ipv4_packet.set_ihl(ihl);
        ipv4_packet.set_dscp(dscp);
        ipv4_packet.set_ecn(ecn);
        ipv4_packet.set_total_length(total_length);
        ipv4_packet.set_identification(identification);
        ipv4_packet.set_flags(flags);
        ipv4_packet.set_fragment_offset(fragment_offset);
        ipv4_packet.set_ttl(ttl);
        ipv4_packet.set_protocol(protocol);
        ipv4_packet.set_src_ip(src_ip);
        ipv4_packet.set_dest_ip(dest_ip);
        ipv4_packet.set_checksum();

        self.pos += ipv4_packet.header_length();

        Ok(self)
    }

    /// Sets the TCP header fields.
    #[inline]
    pub fn tcp(
        &mut self,
        src_ip: &[u8; 4],
        src_port: u16,
        dest_ip: &[u8; 4],
        dest_port: u16,
        sequence_number: u32,
        acknowledgment_number: u32,
        reserved: u8,
        data_offset: u8,
        flags: u8,
        window_size: u16,
        urgent_pointer: u16,
    ) -> Result<&mut Self, &'static str> {
        if self.data.len() < self.pos {
            return Err("Data too short to contain a TCP segment.");
        }

        let mut tcp_packet = TcpSegment::new(&mut self.data[self.pos..])?;

        tcp_packet.set_src_port(src_port);
        tcp_packet.set_dest_port(dest_port);
        tcp_packet.set_sequence_number(sequence_number);
        tcp_packet.set_acknowledgment_number(acknowledgment_number);
        tcp_packet.set_reserved(reserved);
        tcp_packet.set_data_offset(data_offset);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window_size(window_size);
        tcp_packet.set_urgent_pointer(urgent_pointer);
        tcp_packet.set_checksum(&src_ip, &dest_ip);

        self.pos += tcp_packet.header_length();

        Ok(self)
    }

    /// Sets the UDP header fields.
    #[inline]
    pub fn udp(
        &mut self,
        src_ip: &[u8; 4],
        src_port: u16,
        dest_ip: &[u8; 4],
        dest_port: u16,
        length: u16,
    ) -> Result<&mut Self, &'static str> {
        if self.data.len() < self.pos {
            return Err("Data too short to contain a UDP datagram.");
        }

        let mut udp_packet = UdpDatagram::new(&mut self.data[self.pos..])?;

        udp_packet.set_src_port(src_port);
        udp_packet.set_dest_port(dest_port);
        udp_packet.set_length(length);
        udp_packet.set_checksum(&src_ip, &dest_ip);

        self.pos += udp_packet.header_length();

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_in_ipv4_in_ethernet2() {
        // Raw packet data.
        let mut packet = [0u8; 54];

        // Packet builder.
        let mut packet_builder = PacketBuilder::new(&mut packet);

        // Random values for the fields.
        let src_mac = [0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f];
        let dest_mac = [0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7];
        let ethertype = 2048;
        let version = 99;
        let ihl = 5;
        let dscp = 99;
        let ecn = 123;
        let total_length = 12345;
        let identification = 54321;
        let fragment_offset = 12345;
        let ttl = 123;
        let protocol = 6;
        let src_ip = [192, 168, 1, 1];
        let src_port = 99;
        let dest_ip = [192, 168, 1, 2];
        let dest_port = 11;
        let sequence_number = 123;
        let acknowledgment_number = 321;
        let reserved = 11;
        let flags = 99;
        let data_offset = 99;
        let window_size = 4321;
        let urgent_pointer = 1234;

        // Expected output given the chosen values.
        let should_be = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 6, 87, 113, 192, 168, 1, 1, 192, 168, 1, 2, 0, 99, 0, 11, 0, 0, 0, 123,
            0, 0, 1, 65, 59, 99, 16, 225, 41, 81, 4, 210,
        ];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Build the packet.
            packet_builder
                .ethernet(&src_mac, &dest_mac, ethertype)
                .unwrap()
                .ipv4(
                    version,
                    ihl,
                    dscp,
                    ecn,
                    total_length,
                    identification,
                    flags,
                    fragment_offset,
                    ttl,
                    protocol,
                    &src_ip,
                    &dest_ip,
                )
                .unwrap()
                .tcp(
                    &src_ip,
                    src_port,
                    &dest_ip,
                    dest_port,
                    sequence_number,
                    acknowledgment_number,
                    reserved,
                    data_offset,
                    flags,
                    window_size,
                    urgent_pointer,
                )
                .unwrap();
        });

        // Output should match the exepectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn test_udp_in_ipv4_in_ethernet2() {
        // Raw packet data.
        let mut packet = [0u8; 54];

        // Packet builder.
        let mut packet_builder = PacketBuilder::new(&mut packet);

        // Random values for the fields.
        let src_mac = [0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f];
        let dest_mac = [0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7];
        let ethertype = 2048;
        let version = 99;
        let ihl = 5;
        let dscp = 99;
        let ecn = 123;
        let total_length = 12345;
        let identification = 54321;
        let fragment_offset = 12345;
        let ttl = 123;
        let protocol = 6;
        let src_ip = [192, 168, 1, 1];
        let src_port = 99;
        let dest_ip = [192, 168, 1, 2];
        let dest_port = 11;
        let flags = 99;
        let length = 4321;

        // Expected output given the chosen values.
        let should_be = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 6, 87, 113, 192, 168, 1, 1, 192, 168, 1, 2, 0, 99, 0, 11, 16, 225, 107,
            55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Build the packet.
            packet_builder
                .ethernet(&src_mac, &dest_mac, ethertype)
                .unwrap()
                .ipv4(
                    version,
                    ihl,
                    dscp,
                    ecn,
                    total_length,
                    identification,
                    flags,
                    fragment_offset,
                    ttl,
                    protocol,
                    &src_ip,
                    &dest_ip,
                )
                .unwrap()
                .udp(&src_ip, src_port, &dest_ip, dest_port, length)
                .unwrap();
        });

        // Output should match the exepectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }
}
