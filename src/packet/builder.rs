use crate::{
    datalink::{
        arp::ArpBuilder,
        ethernet::{EthernetBuilder, ETHERNET_MIN_HEADER_LENGTH},
    },
    network::{icmp::IcmpBuilder, ipv4::IPv4Builder},
    transport::{tcp::TcpBuilder, udp::UdpBuilder},
};

/// A zero-copy packet builder.
pub struct PacketBuilder<'a> {
    pub data: &'a mut [u8],
    header_len: usize,
}

impl<'a> PacketBuilder<'a> {
    // Ignore clippy lint for too many arguments.
    #![allow(clippy::too_many_arguments)]

    /// Creates a new `PacketBuilder` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> PacketBuilder<'a> {
        PacketBuilder {
            data,
            header_len: 0,
        }
    }

    #[inline]
    /// Returns the length of all encapsulated headers in bytes.
    pub fn total_header_length(&self) -> usize {
        self.header_len
    }

    /// Returns the length of the payload in bytes.
    ///
    /// Should be called after all headers have been set.
    #[inline]
    pub fn payload_length(&self) -> usize {
        self.data.len() - self.header_len
    }

    /// Returns the payload.
    ///
    /// Should be called after all headers have been set.
    #[inline]
    pub fn get_payload(&self) -> &[u8] {
        &self.data[self.header_len..]
    }

    /// Sets the payload.
    ///
    /// Should be called after all headers have been set.
    ///
    /// Fails if the payload is too large to fit in the remaining data slice.
    #[inline]
    pub fn payload(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        if self.data.len() - self.header_len < payload.len() {
            return Err("Data too short to contain the payload.");
        }

        self.data[self.header_len..self.header_len + payload.len()].copy_from_slice(payload);

        Ok(())
    }

    /// Sets Ethernet header fields.
    ///
    /// Should be the first header in the packet.
    #[inline]
    pub fn ethernet(
        &mut self,
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        ethertype: u16,
    ) -> Result<&mut Self, &'static str> {
        let mut ethernet_frame = EthernetBuilder::new(self.data)?;

        ethernet_frame.set_src_mac(src_mac);
        ethernet_frame.set_dest_mac(dest_mac);
        ethernet_frame.set_ethertype(ethertype);

        self.header_len = ETHERNET_MIN_HEADER_LENGTH;

        Ok(self)
    }

    /// Sets ARP header fields.
    ///
    /// Should be encapsulated in an Ethernet frame.
    /// Therefore, should be called after `ethernet`.
    #[inline]
    pub fn arp(
        &mut self,
        hardware_type: u16,
        protocol_type: u16,
        hardware_address_length: u8,
        protocol_address_length: u8,
        operation: u16,
        src_mac: &[u8; 6],
        src_ip: &[u8; 4],
        dest_mac: &[u8; 6],
        dest_ip: &[u8; 4],
    ) -> Result<&mut Self, &'static str> {
        if self.data.len() < self.header_len {
            return Err("Data too short to contain an ARP header.");
        }

        let mut arp_packet = ArpBuilder::new(&mut self.data[self.header_len..])?;

        arp_packet.set_htype(hardware_type);
        arp_packet.set_ptype(protocol_type);
        arp_packet.set_hlen(hardware_address_length);
        arp_packet.set_plen(protocol_address_length);
        arp_packet.set_oper(operation);
        arp_packet.set_sha(src_mac);
        arp_packet.set_spa(src_ip);
        arp_packet.set_tha(dest_mac);
        arp_packet.set_tpa(dest_ip);

        self.header_len += arp_packet.header_length();

        Ok(self)
    }

    /// Sets IPv4 header fields.
    ///
    /// Should be encapsulated in an Ethernet frame.
    /// Therefore, should be called after `ethernet`.
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
        if self.data.len() < self.header_len {
            return Err("Data too short to contain an IPv4 header.");
        }

        let mut ipv4_packet = IPv4Builder::new(&mut self.data[self.header_len..])?;

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

        self.header_len += ipv4_packet.header_length();

        Ok(self)
    }

    /// Sets TCP header fields.
    ///
    /// Should be encapsulated in an IPv4 or IPv6 packet.
    /// Therefore, should be called after `ipv4` or `ipv6`.
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
        if self.data.len() < self.header_len {
            return Err("Data too short to contain a TCP segment.");
        }

        let mut tcp_packet = TcpBuilder::new(&mut self.data[self.header_len..])?;

        tcp_packet.set_src_port(src_port);
        tcp_packet.set_dest_port(dest_port);
        tcp_packet.set_sequence_number(sequence_number);
        tcp_packet.set_acknowledgment_number(acknowledgment_number);
        tcp_packet.set_reserved(reserved);
        tcp_packet.set_data_offset(data_offset);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window_size(window_size);
        tcp_packet.set_urgent_pointer(urgent_pointer);
        tcp_packet.set_checksum(src_ip, dest_ip);

        self.header_len += tcp_packet.header_length();

        Ok(self)
    }

    /// Sets UDP header fields.
    ///
    /// Should be encapsulated in an IPv4 or IPv6 packet.
    /// Therefore, should be called after `ipv4` or `ipv6`.
    #[inline]
    pub fn udp(
        &mut self,
        src_ip: &[u8; 4],
        src_port: u16,
        dest_ip: &[u8; 4],
        dest_port: u16,
        length: u16,
    ) -> Result<&mut Self, &'static str> {
        if self.data.len() < self.header_len {
            return Err("Data too short to contain a UDP datagram.");
        }

        let mut udp_packet = UdpBuilder::new(&mut self.data[self.header_len..])?;

        udp_packet.set_src_port(src_port);
        udp_packet.set_dest_port(dest_port);
        udp_packet.set_length(length);
        udp_packet.set_checksum(src_ip, dest_ip);

        self.header_len += udp_packet.header_length();

        Ok(self)
    }

    /// Sets ICMP header fields.
    ///
    /// Should be encapsulated in an IPv4 or IPv6 packet.
    /// Therefore, should be called after `ipv4` or `ipv6`.
    #[inline]
    pub fn icmp(&mut self, icmp_type: u8, icmp_code: u8) -> Result<&mut Self, &'static str> {
        if self.data.len() < self.header_len {
            return Err("Data too short to contain an ICMP packet.");
        }

        let mut icmp_packet = IcmpBuilder::new(&mut self.data[self.header_len..])?;

        icmp_packet.set_type(icmp_type);
        icmp_packet.set_code(icmp_code);
        icmp_packet.set_checksum();

        self.header_len += icmp_packet.header_length();

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_in_ethernet() {
        // Raw packet data.
        let mut packet = [0u8; 42];

        // Expected output given the chosen values.
        let should_be = [
            255, 255, 255, 255, 255, 255, 52, 151, 246, 148, 2, 15, 8, 6, 0, 1, 8, 0, 6, 4, 0, 1,
            52, 151, 246, 148, 2, 15, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 192, 168, 1, 2,
        ];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Packet builder.
            let mut packet_builder = PacketBuilder::new(&mut packet);

            // Build the packet.
            packet_builder
                .ethernet(
                    &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                    2054,
                )
                .unwrap()
                .arp(
                    1,
                    2048,
                    6,
                    4,
                    1,
                    &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                    &[192, 168, 1, 1],
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    &[192, 168, 1, 2],
                )
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn test_tcp_in_ipv4_in_ethernet() {
        // Raw packet data.
        let mut packet = [0u8; 54];

        // Expected output given the chosen values.
        let should_be = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 6, 87, 113, 192, 168, 1, 1, 192, 168, 1, 2, 0, 99, 0, 11, 0, 0, 0, 123,
            0, 0, 1, 65, 59, 99, 16, 225, 41, 81, 4, 210,
        ];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Packet builder.
            let mut packet_builder = PacketBuilder::new(&mut packet);

            // Build the packet.
            packet_builder
                .ethernet(
                    &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                    &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                    2048,
                )
                .unwrap()
                .ipv4(
                    99,
                    5,
                    99,
                    123,
                    12345,
                    54321,
                    99,
                    12345,
                    123,
                    6,
                    &[192, 168, 1, 1],
                    &[192, 168, 1, 2],
                )
                .unwrap()
                .tcp(
                    &[192, 168, 1, 1],
                    99,
                    &[192, 168, 1, 2],
                    11,
                    123,
                    321,
                    11,
                    99,
                    99,
                    4321,
                    1234,
                )
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn test_udp_in_ipv4_in_ethernet() {
        // Raw packet data.
        let mut packet = [0u8; 54];

        // Expected output given the chosen values.
        let should_be = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 6, 87, 113, 192, 168, 1, 1, 192, 168, 1, 2, 0, 99, 0, 11, 16, 225, 107,
            55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Packet builder.
            let mut packet_builder = PacketBuilder::new(&mut packet);

            // Build the packet.
            packet_builder
                .ethernet(
                    &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                    &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                    2048,
                )
                .unwrap()
                .ipv4(
                    99,
                    5,
                    99,
                    123,
                    12345,
                    54321,
                    99,
                    12345,
                    123,
                    6,
                    &[192, 168, 1, 1],
                    &[192, 168, 1, 2],
                )
                .unwrap()
                .udp(&[192, 168, 1, 1], 99, &[192, 168, 1, 2], 11, 4321)
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn test_icmp_in_ipv4_in_ethernet() {
        // Raw packet data.
        let mut packet = [0u8; 64];

        // Expected output given the chosen values.
        let should_be = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 69, 143, 48, 57, 212, 49,
            112, 57, 123, 1, 71, 118, 192, 168, 1, 1, 192, 168, 1, 2, 8, 0, 247, 255, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Packet builder.
            let mut packet_builder = PacketBuilder::new(&mut packet);

            // Build the packet.
            packet_builder
                .ethernet(
                    &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                    &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                    2048,
                )
                .unwrap()
                .ipv4(
                    4,
                    5,
                    99,
                    123,
                    12345,
                    54321,
                    99,
                    12345,
                    123,
                    1,
                    &[192, 168, 1, 1],
                    &[192, 168, 1, 2],
                )
                .unwrap()
                .icmp(8, 0)
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }
}
