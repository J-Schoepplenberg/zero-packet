use crate::{
    datalink::{
        arp::ArpWriter,
        ethernet::{
            EthernetWriter, ETHERNET_MIN_HEADER_LENGTH, ETHERTYPE_QINQ, ETHERTYPE_VLAN,
            VLAN_TAG_LENGTH,
        },
    },
    network::{
        checksum::{ipv4_pseudo_header, ipv6_pseudo_header},
        icmpv4::Icmpv4Writer,
        icmpv6::Icmpv6Writer,
        ipv4::IPv4Writer,
        ipv6::IPv6Writer,
    },
    transport::{tcp::TcpWriter, udp::UdpWriter},
};

// State Machine:
//
//   Raw
//    |
//    v
// EthernetHeader
//    |       \
//    |        v
//    |    ArpHeader
//    |
//    | +-------------------------> Ipv6Header
//    |                            /        / \
//    v                           /        /   \
// Ipv4Header +------------------/----+   /     \
//    |           \           \ /      \ /       \
//    |            v           v        v         v
//    |      Icmpv4Header TcpHeader UdpHeader Icmpv6Header
//    |            |           |        |         |
//    |            v           v        v         v
//    +-------------------------> Payload < ------+

/// Zero-sized struct representing the `Raw` state of the `PacketBuilder` state machine.
pub struct RawState;

/// Zero-sized struct representing the `EthernetHeader` state of the `PacketBuilder` state machine.
pub struct EthernetHeaderState;

/// Zero-sized struct representing the `ArpHeader` state of the `PacketBuilder` state machine.
pub struct ArpHeaderState;

/// Zero-sized struct representing the `Ipv4Header` state of the `PacketBuilder` state machine.
pub struct Ipv4HeaderState;

/// Zero-sized struct representing the `Ipv6Header` state of the `PacketBuilder` state machine.
pub struct Ipv6HeaderState;

/// Zero-sized struct representing the `TcpHeader` state of the `PacketBuilder` state machine.
pub struct TcpHeaderState;

/// Zero-sized struct representing the `UdpHeader` state of the `PacketBuilder` state machine.
pub struct UdpHeaderState;

/// Zero-sized struct representing the `Icmpv4Header` state of the `PacketBuilder` state machine.
pub struct Icmpv4HeaderState;

/// Zero-sized struct representing the `Icmpv6Header` state of the `PacketBuilder` state machine.
pub struct Icmpv6HeaderState;

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
        let mut writer = EthernetWriter::new(self.bytes)?;

        writer.set_src_mac(src_mac);
        writer.set_dest_mac(dest_mac);
        writer.set_ethertype(ethertype);

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
        let mut writer = EthernetWriter::new(self.bytes)?;

        writer.set_src_mac(src_mac);
        writer.set_dest_mac(dest_mac);
        writer.set_vlan_tag(ETHERTYPE_VLAN, tci)?;
        writer.set_ethertype(ethertype);

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
        let mut writer = EthernetWriter::new(self.bytes)?;

        writer.set_src_mac(src_mac);
        writer.set_dest_mac(dest_mac);
        writer.set_double_vlan_tag(ETHERTYPE_QINQ, tci1, ETHERTYPE_VLAN, tci2)?;
        writer.set_ethertype(ethertype);

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

        let mut writer = ArpWriter::new(&mut self.bytes[self.header_len..])?;

        writer.set_htype(hardware_type);
        writer.set_ptype(protocol_type);
        writer.set_hlen(hardware_address_length);
        writer.set_plen(protocol_address_length);
        writer.set_oper(operation);
        writer.set_sha(src_mac);
        writer.set_spa(src_ip);
        writer.set_tha(dest_mac);
        writer.set_tpa(dest_ip);

        self.header_len += writer.header_len();

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

        let mut writer = IPv4Writer::new(&mut self.bytes[self.header_len..])?;

        writer.set_version(version);
        writer.set_ihl(ihl);
        writer.set_dscp(dscp);
        writer.set_ecn(ecn);
        writer.set_total_length(total_length);
        writer.set_id(identification);
        writer.set_flags(flags);
        writer.set_fragment_offset(fragment_offset);
        writer.set_ttl(ttl);
        writer.set_protocol(protocol);
        writer.set_src_ip(src_ip);
        writer.set_dest_ip(dest_ip);
        writer.set_checksum();

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: Ipv4HeaderState,
        })
    }

    /// Sets IPv6 header fields.
    ///
    /// Transition: EthernetHeader -> Ipv6Header.
    #[inline]
    pub fn ipv6(
        mut self,
        version: u8,
        traffic_class: u8,
        flow_label: u32,
        payload_length: u16,
        next_header: u8,
        hop_limit: u8,
        src_addr: &[u8; 16],
        dest_addr: &[u8; 16],
    ) -> Result<PacketBuilder<'a, Ipv6HeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain an IPv6 header.");
        }

        let mut writer = IPv6Writer::new(&mut self.bytes[self.header_len..])?;

        writer.set_version(version);
        writer.set_traffic_class(traffic_class);
        writer.set_flow_label(flow_label);
        writer.set_payload_length(payload_length);
        writer.set_next_header(next_header);
        writer.set_hop_limit(hop_limit);
        writer.set_src_addr(src_addr);
        writer.set_dest_addr(dest_addr);

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: Ipv6HeaderState,
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

        let mut writer = TcpWriter::new(&mut self.bytes[self.header_len..])?;

        writer.set_src_port(src_port);
        writer.set_dest_port(dest_port);
        writer.set_sequence_number(sequence_number);
        writer.set_ack_number(acknowledgment_number);
        writer.set_reserved(reserved);
        writer.set_data_offset(data_offset);
        writer.set_flags(flags);
        writer.set_window_size(window_size);
        writer.set_urgent_pointer(urgent_pointer);

        let pseudo_sum = ipv4_pseudo_header(src_ip, dest_ip, 6, writer.packet_len());
        writer.set_checksum(pseudo_sum);

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: TcpHeaderState,
        })
    }

    /// Sets UDP header fields.
    ///
    /// Note: checksums are optional if encapsulated in IPv4.
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

        let mut writer = UdpWriter::new(&mut self.bytes[self.header_len..])?;

        writer.set_src_port(src_port);
        writer.set_dest_port(dest_port);
        writer.set_length(length);

        let pseudo_sum = ipv4_pseudo_header(src_ip, dest_ip, 17, writer.packet_len());
        writer.set_checksum(pseudo_sum);

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: UdpHeaderState,
        })
    }

    /// Sets ICMP header fields.
    ///
    /// Transition: Ipv4Header -> Icmpv4Header.
    #[inline]
    pub fn icmpv4(
        mut self,
        icmp_type: u8,
        icmp_code: u8,
    ) -> Result<PacketBuilder<'a, Icmpv4HeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain an ICMP packet.");
        }

        let mut writer = Icmpv4Writer::new(&mut self.bytes[self.header_len..])?;

        writer.set_icmp_type(icmp_type);
        writer.set_icmp_code(icmp_code);
        writer.set_checksum();

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: Icmpv4HeaderState,
        })
    }
}

impl<'a> PacketBuilder<'a, Ipv6HeaderState> {
    /// Sets TCP header fields.
    ///
    /// Transition: Ipv6Header -> TcpHeader.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn tcp(
        mut self,
        src_addr: &[u8; 16],
        src_port: u16,
        dest_addr: &[u8; 16],
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

        let mut writer = TcpWriter::new(&mut self.bytes[self.header_len..])?;

        writer.set_src_port(src_port);
        writer.set_dest_port(dest_port);
        writer.set_sequence_number(sequence_number);
        writer.set_ack_number(acknowledgment_number);
        writer.set_reserved(reserved);
        writer.set_data_offset(data_offset);
        writer.set_flags(flags);
        writer.set_window_size(window_size);
        writer.set_urgent_pointer(urgent_pointer);

        let pseudo_sum = ipv6_pseudo_header(src_addr, dest_addr, 6, writer.packet_len());
        writer.set_checksum(pseudo_sum);

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: TcpHeaderState,
        })
    }

    /// Sets UDP header fields.
    ///
    /// Note: checksums are mandatory if encapsulated in IPv6.
    ///
    /// Transition: Ipv6Header -> UdpHeader.
    #[inline]
    pub fn udp(
        mut self,
        src_addr: &[u8; 16],
        src_port: u16,
        dest_addr: &[u8; 16],
        dest_port: u16,
        length: u16,
    ) -> Result<PacketBuilder<'a, UdpHeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain a UDP datagram.");
        }

        let mut writer = UdpWriter::new(&mut self.bytes[self.header_len..])?;

        writer.set_src_port(src_port);
        writer.set_dest_port(dest_port);
        writer.set_length(length);

        let pseudo_sum = ipv6_pseudo_header(src_addr, dest_addr, 17, writer.packet_len());
        writer.set_checksum(pseudo_sum);

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: UdpHeaderState,
        })
    }

    /// Sets ICMPv6 header fields.
    ///
    /// Transition: Ipv6Header -> Icmpv6Header.
    #[inline]
    pub fn icmpv6(
        mut self,
        src_addr: &[u8; 16],
        dest_addr: &[u8; 16],
        icmp_type: u8,
        icmp_code: u8,
    ) -> Result<PacketBuilder<'a, Icmpv6HeaderState>, &'static str> {
        if self.bytes.len() < self.header_len {
            return Err("Data too short to contain an ICMPv6 packet.");
        }

        let mut writer = Icmpv6Writer::new(&mut self.bytes[self.header_len..])?;

        writer.set_icmp_type(icmp_type);
        writer.set_icmp_code(icmp_code);

        let pseudo_sum = ipv6_pseudo_header(src_addr, dest_addr, 58, writer.packet_len());
        writer.set_checksum(pseudo_sum);

        self.header_len += writer.header_len();

        Ok(PacketBuilder {
            bytes: self.bytes,
            header_len: self.header_len,
            _state: Icmpv6HeaderState,
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

impl<'a> PayloadWriter<'a> for PacketBuilder<'a, Icmpv4HeaderState> {
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

impl<'a> PayloadWriter<'a> for PacketBuilder<'a, Icmpv6HeaderState> {
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
        packet::parser::PacketParser, transport::udp::UDP_HEADER_LENGTH,
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
    fn test_icmpv4_in_ipv4_in_ethernet() {
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
                .icmpv4(8, 0)
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn test_build_parse_ipv6() {
        // IPv6 source address.
        let src_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];

        // IPv6 destination address.
        let dest_addr = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0xb3, 0xff, 0xfe, 0x1e,
            0x83, 0x29,
        ];

        // Raw packet data.
        let mut buffer = [0u8; 64];

        // Build the packet.
        let packet = PacketBuilder::new(&mut buffer)
            .ethernet(
                &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                34525,
            )
            .unwrap()
            .ipv6(6, 5, 4, 31, 17, 10, &src_addr, &dest_addr)
            .unwrap()
            .udp(&src_addr, 99, &dest_addr, 80, 10)
            .unwrap()
            .build();

        // Expected output given the chosen values. Checksum should be (21, 45).
        assert_eq!(
            packet,
            [
                4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 134, 221, 96, 80, 0, 4, 0,
                31, 17, 10, 32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52, 254,
                128, 0, 0, 0, 0, 0, 0, 2, 2, 179, 255, 254, 30, 131, 41, 0, 99, 0, 80, 0, 10, 21,
                45, 0, 0
            ]
        );

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser is successful.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the expected headers are present.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv6.is_some());
        assert!(unwrapped.udp.is_some());

        // Ensure the unexpected headers are not present.
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.tcp.is_none());
    }

    #[test]
    fn test_build_parse_qinq() {
        // Raw packet data.
        let mut buffer = [0u8; 64];

        // Build a valid packet
        let packet = PacketBuilder::new(&mut buffer)
            // 22 bytes
            .ethernet_qinq(
                &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                2048,
                200,
                100,
            )
            .unwrap()
            // 20 bytes
            .ipv4(
                4,
                5,
                99,
                123,
                42,
                54321,
                99,
                12345,
                123,
                17,
                &[192, 168, 1, 1],
                &[192, 168, 1, 2],
            )
            .unwrap()
            // 8 bytes
            .udp(&[192, 168, 1, 1], 99, &[192, 168, 1, 2], 11, 22)
            .unwrap()
            .build();

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser is successful.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the expected headers are present.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv4.is_some());
        assert!(unwrapped.udp.is_some());

        // Ensure the unexpected headers are not present.
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.tcp.is_none());

        // Unwrap ethernet.
        let ethernet = unwrapped.ethernet.unwrap();

        // Ensure expected VLAN tags are present.
        assert!(ethernet.vlan_tag().is_none());
        assert!(ethernet.double_vlan_tag().is_some());

        // Ensure the expected fields are present.
        assert_eq!(ethernet.src_mac(), [0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f]);
        assert_eq!(ethernet.dest_mac(), [0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7]);
        assert_eq!(ethernet.ethertype(), 2048);
        assert_eq!(
            ethernet.double_vlan_tag().unwrap(),
            ((ETHERTYPE_QINQ, 200), (ETHERTYPE_VLAN, 100))
        );
    }

    #[test]
    fn test_build_parse_qinq_icmpv6() {
        // Raw packet data.
        let mut buffer = [0u8; 70];

        // IPv6 source address.
        let src_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];

        // IPv6 destination address.
        let dest_addr = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0xb3, 0xff, 0xfe, 0x1e,
            0x83, 0x29,
        ];

        // Build a valid packet
        let packet = PacketBuilder::new(&mut buffer)
            // 22 bytes
            .ethernet_qinq(
                &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                34525,
                200,
                100,
            )
            .unwrap()
            // 60 bytes
            .ipv6(6, 5, 4, 3, 58, 255, &src_addr, &dest_addr)
            .unwrap()
            // 8 bytes
            .icmpv6(&src_addr, &dest_addr, 128, 0)
            .unwrap()
            .build();

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser is successful.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let unwrapped = parser.unwrap();

        // Ensure the expected headers are present.
        assert!(unwrapped.ethernet.is_some());
        assert!(unwrapped.ipv6.is_some());
        assert!(unwrapped.icmpv6.is_some());

        // Ensure the unexpected headers are not present.
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.udp.is_none());
        assert!(unwrapped.tcp.is_none());
        assert!(unwrapped.icmpv4.is_none());
    }
}
