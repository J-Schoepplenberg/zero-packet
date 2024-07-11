use crate::{
    datalink::{
        arp::ArpWriter,
        ethernet::{
            EthernetWriter, ETHERNET_MIN_HEADER_LENGTH, ETHERTYPE_QINQ, ETHERTYPE_VLAN,
            VLAN_TAG_LENGTH,
        },
    },
    network::{icmp::IcmpWriter, ipv4::IPv4Writer},
    transport::{tcp::TcpWriter, udp::UdpWriter},
};

// PacketBuilder State Machine:
//
//   Raw
//    |
//    v
// EthernetHeader
//    |       \
//    |        v
//    |     ArpHeader
//    |
//    v
// Ipv4Header
//    |     \         \           \
//    |      v         v           v
//    |   TcpHeader  UdpHeader  IcmpHeader
//    |      |         |           |
//    |      v         v           v
//    +-----------> Payload <------+

/// Zero-sized struct representing the `Raw` state of the `PacketBuilder` state machine.
pub struct RawState;

/// Zero-sized struct representing the `EthernetHeader` state of the `PacketBuilder` state machine.
pub struct EthernetHeaderState;

/// Zero-sized struct representing the `ArpHeader` state of the `PacketBuilder` state machine.
pub struct ArpHeaderState;

/// Zero-sized struct representing the `Ipv4Header` state of the `PacketBuilder` state machine.
pub struct Ipv4HeaderState;

/// Zero-sized struct representing the `TcpHeader` state of the `PacketBuilder` state machine.
pub struct TcpHeaderState;

/// Zero-sized struct representing the `UdpHeader` state of the `PacketBuilder` state machine.
pub struct UdpHeaderState;

/// Zero-sized struct representing the `IcmpHeader` state of the `PacketBuilder` state machine.
pub struct IcmpHeaderState;

/// Zero-sized struct representing the `Payload` state of the `PacketBuilder` state machine.
pub struct PayloadState;

/// A zero-copy packet builder.
///
/// Using the typestate pattern, a state machine is implemented using the type system.
/// The state machine ensures that the package is built correctly.
///
/// The creation of new `PacketBuilder` instances happens on the stack.
/// These stack allocations are very cheap and most likely optimized away by the compiler.
/// The state types are zero-sized types (ZSTs) and don't consume any memory.
pub struct PacketBuilder<'a, State> {
    bytes: &'a mut [u8],
    header_len: usize,
    _state: State,
}

impl<'a, State> PacketBuilder<'a, State> {
    /// Returns the length of all encapsulated headers in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns the length of the payload in bytes.
    ///
    /// Payload is the data after all headers.
    #[inline]
    pub fn payload_len(&self) -> usize {
        self.bytes.len() - self.header_len
    }

    /// Returns a reference to the payload.
    ///
    /// Payload is the data after all headers.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_len..]
    }

    /// Returns a reference to the data slice.
    #[inline]
    pub fn build(self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a> PacketBuilder<'a, RawState> {
    /// Creates a new `PacketBuilder` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> PacketBuilder<'a, RawState> {
        PacketBuilder {
            bytes,
            header_len: 0,
            _state: RawState,
        }
    }

    /// Sets Ethernet II header fields.
    ///
    /// Transition: Raw -> EthernetHeader.
    #[inline]
    pub fn ethernet(
        mut self,
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        ethertype: u16,
    ) -> Result<PacketBuilder<'a, EthernetHeaderState>, &'static str> {
        let mut ethernet_frame = EthernetWriter::new(self.bytes)?;

        ethernet_frame.set_src_mac(src_mac);
        ethernet_frame.set_dest_mac(dest_mac);
        ethernet_frame.set_ethertype(ethertype);

        self.header_len = ETHERNET_MIN_HEADER_LENGTH;

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: EthernetHeaderState,
        })
    }

    /// Sets Ethernet II header fields with VLAN tagging.
    ///
    /// Transition: Raw -> EthernetHeader.
    pub fn ethernet_vlan(
        mut self,
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        ethertype: u16,
        tci: u16,
    ) -> Result<PacketBuilder<'a, EthernetHeaderState>, &'static str> {
        let mut ethernet_frame = EthernetWriter::new(self.bytes)?;

        ethernet_frame.set_src_mac(src_mac);
        ethernet_frame.set_dest_mac(dest_mac);
        ethernet_frame.set_vlan_tag(ETHERTYPE_VLAN, tci)?;
        ethernet_frame.set_ethertype(ethertype);

        self.header_len = ETHERNET_MIN_HEADER_LENGTH + VLAN_TAG_LENGTH;

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: EthernetHeaderState,
        })
    }

    /// Sets Ethernet II header fields with double VLAN tagging.
    ///
    /// Transition: Raw -> EthernetHeader.
    pub fn ethernet_qinq(
        mut self,
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        ethertype: u16,
        tci1: u16,
        tci2: u16,
    ) -> Result<PacketBuilder<'a, EthernetHeaderState>, &'static str> {
        let mut ethernet_frame = EthernetWriter::new(self.bytes)?;

        ethernet_frame.set_src_mac(src_mac);
        ethernet_frame.set_dest_mac(dest_mac);
        ethernet_frame.set_double_vlan_tag(ETHERTYPE_QINQ, tci1, ETHERTYPE_VLAN, tci2)?;
        ethernet_frame.set_ethertype(ethertype);

        self.header_len = ETHERNET_MIN_HEADER_LENGTH + 2 * VLAN_TAG_LENGTH;

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: EthernetHeaderState,
        })
    }
}

impl<'a> PacketBuilder<'a, EthernetHeaderState> {
    /// Sets ARP header fields.
    ///
    /// Transition: EthernetHeader -> ArpHeader.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn arp(
        mut self,
        hardware_type: u16,
        protocol_type: u16,
        hardware_address_length: u8,
        protocol_address_length: u8,
        operation: u16,
        src_mac: &[u8; 6],
        src_ip: &[u8; 4],
        dest_mac: &[u8; 6],
        dest_ip: &[u8; 4],
    ) -> Result<PacketBuilder<'a, ArpHeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain an ARP header.");
        }

        let mut arp_packet = ArpWriter::new(&mut self.bytes[self.header_len..])?;

        arp_packet.set_htype(hardware_type);
        arp_packet.set_ptype(protocol_type);
        arp_packet.set_hlen(hardware_address_length);
        arp_packet.set_plen(protocol_address_length);
        arp_packet.set_oper(operation);
        arp_packet.set_sha(src_mac);
        arp_packet.set_spa(src_ip);
        arp_packet.set_tha(dest_mac);
        arp_packet.set_tpa(dest_ip);

        self.header_len += arp_packet.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: ArpHeaderState,
        })
    }

    /// Sets IPv4 header fields.
    ///
    /// Transition: EthernetHeader -> Ipv4Header.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn ipv4(
        mut self,
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
    ) -> Result<PacketBuilder<'a, Ipv4HeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain an IPv4 header.");
        }

        let mut ipv4_packet = IPv4Writer::new(&mut self.bytes[self.header_len..])?;

        ipv4_packet.set_version(version);
        ipv4_packet.set_ihl(ihl);
        ipv4_packet.set_dscp(dscp);
        ipv4_packet.set_ecn(ecn);
        ipv4_packet.set_total_length(total_length);
        ipv4_packet.set_id(identification);
        ipv4_packet.set_flags(flags);
        ipv4_packet.set_fragment_offset(fragment_offset);
        ipv4_packet.set_ttl(ttl);
        ipv4_packet.set_protocol(protocol);
        ipv4_packet.set_src_ip(src_ip);
        ipv4_packet.set_dest_ip(dest_ip);
        ipv4_packet.set_checksum();

        self.header_len += ipv4_packet.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: Ipv4HeaderState,
        })
    }
}

impl<'a> PacketBuilder<'a, Ipv4HeaderState> {
    /// Sets TCP header fields.
    ///
    /// Transition: Ipv4Header -> TcpHeader.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn tcp(
        mut self,
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
    ) -> Result<PacketBuilder<'a, TcpHeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain a TCP segment.");
        }

        let mut tcp_packet = TcpWriter::new(&mut self.bytes[self.header_len..])?;

        tcp_packet.set_src_port(src_port);
        tcp_packet.set_dest_port(dest_port);
        tcp_packet.set_sequence_number(sequence_number);
        tcp_packet.set_ack_number(acknowledgment_number);
        tcp_packet.set_reserved(reserved);
        tcp_packet.set_data_offset(data_offset);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window_size(window_size);
        tcp_packet.set_urgent_pointer(urgent_pointer);
        tcp_packet.set_checksum(src_ip, dest_ip);

        self.header_len += tcp_packet.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: TcpHeaderState,
        })
    }

    /// Sets UDP header fields.
    ///
    /// Transition: Ipv4Header -> UdpHeader.
    #[inline]
    pub fn udp(
        mut self,
        src_ip: &[u8; 4],
        src_port: u16,
        dest_ip: &[u8; 4],
        dest_port: u16,
        length: u16,
    ) -> Result<PacketBuilder<'a, UdpHeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain a UDP datagram.");
        }

        let mut udp_packet = UdpWriter::new(&mut self.bytes[self.header_len..])?;

        udp_packet.set_src_port(src_port);
        udp_packet.set_dest_port(dest_port);
        udp_packet.set_length(length);
        udp_packet.set_checksum(src_ip, dest_ip);

        self.header_len += udp_packet.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: UdpHeaderState,
        })
    }

    /// Sets ICMP header fields.
    ///
    /// Transition: Ipv4Header -> IcmpHeader.
    #[inline]
    pub fn icmp(
        mut self,
        icmp_type: u8,
        icmp_code: u8,
    ) -> Result<PacketBuilder<'a, IcmpHeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain an ICMP packet.");
        }

        let mut icmp_packet = IcmpWriter::new(&mut self.bytes[self.header_len..])?;

        icmp_packet.set_icmp_type(icmp_type);
        icmp_packet.set_icmp_code(icmp_code);
        icmp_packet.set_checksum();

        self.header_len += icmp_packet.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: IcmpHeaderState,
        })
    }
}

/// Interface for writing the payload for a packet.
///
/// Implemented for `PacketBuilder` in the `TcpHeader`, `UdpHeader`, and `IcmpHeader` states.
pub trait PayloadWriter<'a> {
    /// Writes a given payload to the packet and transitions into the `Payload` state.
    ///
    /// `PacketBuilder::payload_len()` may be different than the written payload.
    ///
    /// That is, because the data slice, which we mutate in-place, can be longer than the payload.
    fn write_payload(self, payload: &[u8])
        -> Result<PacketBuilder<'a, PayloadState>, &'static str>;
}

impl<'a> PayloadWriter<'a> for PacketBuilder<'a, TcpHeaderState> {
    #[inline]
    fn write_payload(
        self,
        payload: &[u8],
    ) -> Result<PacketBuilder<'a, PayloadState>, &'static str> {
        if self.bytes.len() - self.header_len < payload.len() {
            return Err("Data too short to contain the payload.");
        }

        let payload_start = self.header_len;
        let payload_end = payload_start + payload.len();
        self.bytes[payload_start..payload_end].copy_from_slice(payload);

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: PayloadState,
        })
    }
}

impl<'a> PayloadWriter<'a> for PacketBuilder<'a, UdpHeaderState> {
    #[inline]
    fn write_payload(
        self,
        payload: &[u8],
    ) -> Result<PacketBuilder<'a, PayloadState>, &'static str> {
        if self.bytes.len() - self.header_len < payload.len() {
            return Err("Data too short to contain the payload.");
        }

        let payload_start = self.header_len;
        let payload_end = payload_start + payload.len();
        self.bytes[payload_start..payload_end].copy_from_slice(payload);

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: PayloadState,
        })
    }
}

impl<'a> PayloadWriter<'a> for PacketBuilder<'a, IcmpHeaderState> {
    #[inline]
    fn write_payload(
        self,
        payload: &[u8],
    ) -> Result<PacketBuilder<'a, PayloadState>, &'static str> {
        if self.bytes.len() - self.header_len < payload.len() {
            return Err("Data too short to contain the payload.");
        }

        let payload_start = self.header_len;
        let payload_end = payload_start + payload.len();
        self.bytes[payload_start..payload_end].copy_from_slice(payload);

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: PayloadState,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datalink::arp::ARP_HEADER_LENGTH, network::ipv4::IPV4_MIN_HEADER_LENGTH,
        transport::udp::UDP_HEADER_LENGTH,
    };

    #[test]
    fn test_write_payload() {
        // Raw packet data.
        let mut buffer = [0u8; 64];

        // Construct PacketBuilder with an Ethernet header, an IPv4 header, a UDP header, and a payload.
        let packet_builder = PacketBuilder::new(&mut buffer)
            .ethernet(&[1, 2, 3, 4, 5, 6], &[7, 8, 9, 10, 11, 12], 0x0800)
            .unwrap()
            .ipv4(
                4,
                5,
                0,
                0,
                0,
                0,
                0,
                0,
                64,
                1,
                &[192, 168, 1, 1],
                &[192, 168, 1, 2],
            )
            .unwrap()
            .udp(&[192, 168, 1, 1], 12345, &[192, 168, 1, 2], 54321, 0)
            .unwrap()
            .write_payload(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            .unwrap();

        // Ensure the header length is correct.
        assert_eq!(
            packet_builder.header_len(),
            ETHERNET_MIN_HEADER_LENGTH + IPV4_MIN_HEADER_LENGTH + UDP_HEADER_LENGTH
        );

        // Since the buffer slice is bigger than the header length + written payload length,
        // the data that follows all headers is not the same as the written payload.
        assert_ne!(
            packet_builder.payload_len(),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].len()
        );

        // Build the packet.
        let packet = packet_builder.build();

        // Expected output given the chosen values.
        let should_be = [
            7, 8, 9, 10, 11, 12, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 0, 0, 0, 0, 0, 64, 1, 247, 169,
            192, 168, 1, 1, 192, 168, 1, 2, 48, 57, 212, 49, 0, 0, 120, 17, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Output should match the exepectation.
        assert_eq!(packet, should_be);
    }

    #[test]
    fn test_misc() {
        // Raw packet data.
        let mut packet = [0u8; 64];

        // Measure the number of allocations.
        let allocations = allocation_counter::measure(|| {
            // Packet builder in the initial state.
            let packet_builder = PacketBuilder::new(&mut packet);

            // Transition to the Ethernet header state.
            let eth_builder = packet_builder
                .ethernet(
                    &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                    2054,
                )
                .unwrap();

            // Ensure the header length is correct.
            assert_eq!(eth_builder.header_len(), ETHERNET_MIN_HEADER_LENGTH);

            // Transition to the ARP header state.
            let arp_builder = eth_builder
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

            // Ensure the header length is correct.
            assert_eq!(
                arp_builder.header_len(),
                ETHERNET_MIN_HEADER_LENGTH + ARP_HEADER_LENGTH
            );

            // Ensure 64 (Raw) - 14 (Ethernet) - 28 (Arp) = 22.
            assert_eq!(arp_builder.payload_len(), 22);
        });

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

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
            let packet_builder = PacketBuilder::new(&mut packet);

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
            let packet_builder = PacketBuilder::new(&mut packet);

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
            let packet_builder = PacketBuilder::new(&mut packet);

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
            let packet_builder = PacketBuilder::new(&mut packet);

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
