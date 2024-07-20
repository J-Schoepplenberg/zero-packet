use crate::{
    datalink::{
        arp::ArpWriter,
        ethernet::{
            EthernetWriter, ETHERNET_MIN_HEADER_LENGTH, ETHERTYPE_QINQ, ETHERTYPE_VLAN,
            VLAN_TAG_LENGTH,
        },
    },
    network::{
        checksum::pseudo_header,
        extensions::{
            authentication::AuthenticationHeaderWriter, fragment::FragmentHeaderWriter,
            options::OptionsHeaderWriter, routing::RoutingHeaderWriter,
        },
        icmpv4::Icmpv4Writer,
        icmpv6::Icmpv6Writer,
        ipv4::IPv4Writer,
        ipv6::IPv6Writer,
    },
    transport::{tcp::TcpWriter, udp::UdpWriter},
};

// Note:
// Implementing a builder pattern for packet construction using the typestate pattern.
// The typestate pattern encodes state transitions in the type system at compile-time.
// This pattern is used to ensure that the packet is built structurally correct.

// State machine states. Zero-sized structs (ZSTs).
pub struct RawState;
pub struct EthernetHeaderState;
pub struct ArpHeaderState;
pub struct Ipv4HeaderState;
pub struct Ipv6HeaderState;
pub struct TcpHeaderState;
pub struct UdpHeaderState;
pub struct Icmpv4HeaderState;
pub struct Icmpv6HeaderState;
pub struct Ipv4EncapsulatedState;
pub struct Ipv6EncapsulatedState;
pub struct HopByHopOptionsState;
pub struct DestinationOptions1State;
pub struct DestinationOptions2State;
pub struct RoutingHeaderState;
pub struct FragmentHeaderState;
pub struct AuthHeaderState;

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

// All states share these methods.
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

// Usage of macros to reduce code duplication.

macro_rules! impl_raw {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn new(bytes: &'a mut [u8]) -> PacketBuilder<'a, RawState> {
                PacketBuilder {
                    bytes,
                    header_len: 0,
                    _state: RawState,
                }
            }
        }
    };
}

macro_rules! impl_ethernet {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
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
        }
    };
}

macro_rules! impl_ethernet_vlan {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
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
        }
    };
}

macro_rules! impl_ethernet_qinq {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
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
    };
}

macro_rules! impl_arp {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            #[allow(clippy::too_many_arguments)]
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
        }
    };
}

macro_rules! impl_ipv4 {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            #[allow(clippy::too_many_arguments)]
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
        }
    };
}

macro_rules! impl_ipv6 {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            #[allow(clippy::too_many_arguments)]
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
    };
}

macro_rules! impl_ipv4_encapsulated {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            #[allow(clippy::too_many_arguments)]
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
            ) -> Result<PacketBuilder<'a, Ipv4EncapsulatedState>, &'static str> {
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
                    _state: Ipv4EncapsulatedState,
                })
            }
        }
    };
}

macro_rules! impl_ipv6_encapsulated {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            #[allow(clippy::too_many_arguments)]
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
            ) -> Result<PacketBuilder<'a, Ipv6EncapsulatedState>, &'static str> {
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
                    _state: Ipv6EncapsulatedState,
                })
            }
        }
    };
}

macro_rules! impl_tcp {
    ($state:ty, $addr_type:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[allow(clippy::too_many_arguments)]
            #[inline]
            pub fn tcp(
                mut self,
                src_ip: $addr_type,
                src_port: u16,
                dest_ip: $addr_type,
                dest_port: u16,
                sequence_number: u32,
                acknowledgment_number: u32,
                data_offset: u8,
                reserved: u8,
                flags: u8,
                window_size: u16,
                urgent_pointer: u16,
                payload: Option<&[u8]>,
            ) -> Result<PacketBuilder<'a, TcpHeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain a TCP segment.");
                }

                let mut writer = TcpWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_src_port(src_port);
                writer.set_dest_port(dest_port);
                writer.set_sequence_number(sequence_number);
                writer.set_ack_number(acknowledgment_number);
                writer.set_data_offset(data_offset);
                writer.set_reserved(reserved);
                writer.set_flags(flags);
                writer.set_window_size(window_size);
                writer.set_urgent_pointer(urgent_pointer);

                if let Some(payload) = payload {
                    writer.set_payload(payload)?;
                }

                let pseudo_sum = pseudo_header(src_ip, dest_ip, 6, writer.packet_len());
                writer.set_checksum(pseudo_sum);

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: TcpHeaderState,
                })
            }
        }
    };
}

macro_rules! impl_udp {
    ($state:ty, $addr_type:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn udp(
                mut self,
                src_addr: $addr_type,
                src_port: u16,
                dest_addr: $addr_type,
                dest_port: u16,
                length: u16,
                payload: Option<&[u8]>,
            ) -> Result<PacketBuilder<'a, UdpHeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain a UDP datagram.");
                }

                let mut writer = UdpWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_src_port(src_port);
                writer.set_dest_port(dest_port);
                writer.set_length(length);

                if let Some(payload) = payload {
                    writer.set_payload(payload)?;
                }

                let pseudo_sum = pseudo_header(src_addr, dest_addr, 17, writer.packet_len());
                writer.set_checksum(pseudo_sum);

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: UdpHeaderState,
                })
            }
        }
    };
}

macro_rules! impl_icmpv4 {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn icmpv4(
                mut self,
                icmp_type: u8,
                icmp_code: u8,
                payload: Option<&[u8]>,
            ) -> Result<PacketBuilder<'a, Icmpv4HeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an ICMP packet.");
                }

                let mut writer = Icmpv4Writer::new(&mut self.bytes[self.header_len..])?;

                writer.set_icmp_type(icmp_type);
                writer.set_icmp_code(icmp_code);

                if let Some(payload) = payload {
                    writer.set_payload(payload)?;
                }

                writer.set_checksum();

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: Icmpv4HeaderState,
                })
            }
        }
    };
}

macro_rules! impl_icmpv6 {
    ($state:ty, $addr_type:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn icmpv6(
                mut self,
                src_addr: $addr_type,
                dest_addr: $addr_type,
                icmp_type: u8,
                icmp_code: u8,
                payload: Option<&[u8]>,
            ) -> Result<PacketBuilder<'a, Icmpv6HeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an ICMPv6 packet.");
                }

                let mut writer = Icmpv6Writer::new(&mut self.bytes[self.header_len..])?;

                writer.set_icmp_type(icmp_type);
                writer.set_icmp_code(icmp_code);

                if let Some(payload) = payload {
                    writer.set_payload(payload)?;
                }

                let pseudo_sum = pseudo_header(src_addr, dest_addr, 58, writer.packet_len());
                writer.set_checksum(pseudo_sum);

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: Icmpv6HeaderState,
                })
            }
        }
    };
}

macro_rules! impl_hop_by_hop {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn hop_by_hop(
                mut self,
                next_header: u8,
                extension_len: u8,
                options: &[u8],
            ) -> Result<PacketBuilder<'a, HopByHopOptionsState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an IPv6 Hop-by-Hop Options header.");
                }

                let mut writer = OptionsHeaderWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_next_header(next_header);
                writer.set_header_ext_len(extension_len);
                writer.set_options(options)?;

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: HopByHopOptionsState,
                })
            }
        }
    };
}

macro_rules! impl_destination_options_1 {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn destination_options1(
                mut self,
                next_header: u8,
                extension_len: u8,
                options: &[u8],
            ) -> Result<PacketBuilder<'a, DestinationOptions1State>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an IPv6 Destination Options header.");
                }

                let mut writer = OptionsHeaderWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_next_header(next_header);
                writer.set_header_ext_len(extension_len);
                writer.set_options(options)?;

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: DestinationOptions1State,
                })
            }
        }
    };
}

macro_rules! impl_routing_header {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn routing_header(
                mut self,
                next_header: u8,
                header_ext_len: u8,
                routing_type: u8,
                segments_left: u8,
                data: &[u8],
            ) -> Result<PacketBuilder<'a, RoutingHeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an IPv6 Routing header.");
                }

                let mut writer = RoutingHeaderWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_next_header(next_header);
                writer.set_header_ext_len(header_ext_len);
                writer.set_routing_type(routing_type);
                writer.set_segments_left(segments_left);
                writer.set_data(data)?;

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: RoutingHeaderState,
                })
            }
        }
    };
}

macro_rules! impl_fragment_header {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn fragment_header(
                mut self,
                next_header: u8,
                fragment_offset: u16,
                m_flag: bool,
                identification: u32,
            ) -> Result<PacketBuilder<'a, FragmentHeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an IPv6 Routing header.");
                }

                let mut writer = FragmentHeaderWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_next_header(next_header);
                writer.set_reserved(0);
                writer.set_fragment_offset(fragment_offset);
                writer.set_res(0);
                writer.set_m_flag(m_flag);
                writer.set_identification(identification);

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: FragmentHeaderState,
                })
            }
        }
    };
}

macro_rules! impl_authentication_header {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn authentication_header(
                mut self,
                next_header: u8,
                payload_len: u8,
                spi: u32,
                seq_num: u32,
                auth_data: &[u8],
            ) -> Result<PacketBuilder<'a, AuthHeaderState>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an IPv6 Authentication header.");
                }

                let mut writer =
                    AuthenticationHeaderWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_next_header(next_header);
                writer.set_payload_len(payload_len);
                writer.set_reserved(0);
                writer.set_spi(spi);
                writer.set_sequence_number(seq_num);
                writer.set_authentication_data(auth_data)?;

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: AuthHeaderState,
                })
            }
        }
    };
}

macro_rules! impl_destination_options_2 {
    ($state:ty) => {
        impl<'a> PacketBuilder<'a, $state> {
            #[inline]
            pub fn destination_options2(
                mut self,
                next_header: u8,
                extension_len: u8,
                options: &[u8],
            ) -> Result<PacketBuilder<'a, DestinationOptions2State>, &'static str> {
                if self.bytes.len() < self.header_len {
                    return Err("Data too short to contain an IPv6 Destination Options header.");
                }

                let mut writer = OptionsHeaderWriter::new(&mut self.bytes[self.header_len..])?;

                writer.set_next_header(next_header);
                writer.set_header_ext_len(extension_len);
                writer.set_options(options)?;

                self.header_len += writer.header_len();

                Ok(PacketBuilder {
                    bytes: self.bytes,
                    header_len: self.header_len,
                    _state: DestinationOptions2State,
                })
            }
        }
    };
}

// Implementing the state machine transitions.
// We adhere to the recommended extension header order according to RFC 2460.

// Raw
impl_raw!(RawState);
impl_ethernet!(RawState);
impl_ethernet_vlan!(RawState);
impl_ethernet_qinq!(RawState);

// EthernetHeader
impl_arp!(EthernetHeaderState);
impl_ipv4!(EthernetHeaderState);
impl_ipv6!(EthernetHeaderState);

// Ipv4Encapsulated
impl_tcp!(Ipv4EncapsulatedState, &[u8; 4]);
impl_udp!(Ipv4EncapsulatedState, &[u8; 4]);
impl_icmpv4!(Ipv4EncapsulatedState);

// Ipv6Encapsulated
impl_tcp!(Ipv6EncapsulatedState, &[u8; 16]);
impl_udp!(Ipv6EncapsulatedState, &[u8; 16]);
impl_icmpv6!(Ipv6EncapsulatedState, &[u8; 16]);

// IPv4Header
impl_tcp!(Ipv4HeaderState, &[u8; 4]);
impl_udp!(Ipv4HeaderState, &[u8; 4]);
impl_icmpv4!(Ipv4HeaderState);
impl_ipv4_encapsulated!(Ipv4HeaderState);
impl_ipv6_encapsulated!(Ipv4HeaderState);

// IPv6Header
impl_tcp!(Ipv6HeaderState, &[u8; 16]);
impl_udp!(Ipv6HeaderState, &[u8; 16]);
impl_icmpv6!(Ipv6HeaderState, &[u8; 16]);
impl_ipv4_encapsulated!(Ipv6HeaderState);
impl_ipv6_encapsulated!(Ipv6HeaderState);
impl_hop_by_hop!(Ipv6HeaderState);
impl_destination_options_1!(Ipv6HeaderState);
impl_routing_header!(Ipv6HeaderState);
impl_fragment_header!(Ipv6HeaderState);
impl_authentication_header!(Ipv6HeaderState);
impl_destination_options_2!(Ipv6HeaderState);

// HopByHopOptions
impl_tcp!(HopByHopOptionsState, &[u8; 16]);
impl_udp!(HopByHopOptionsState, &[u8; 16]);
impl_icmpv6!(HopByHopOptionsState, &[u8; 16]);
impl_ipv4_encapsulated!(HopByHopOptionsState);
impl_ipv6_encapsulated!(HopByHopOptionsState);
impl_destination_options_1!(HopByHopOptionsState);
impl_routing_header!(HopByHopOptionsState);
impl_fragment_header!(HopByHopOptionsState);
impl_authentication_header!(HopByHopOptionsState);
impl_destination_options_2!(HopByHopOptionsState);

// DestinationOptions1
impl_tcp!(DestinationOptions1State, &[u8; 16]);
impl_udp!(DestinationOptions1State, &[u8; 16]);
impl_icmpv6!(DestinationOptions1State, &[u8; 16]);
impl_ipv4_encapsulated!(DestinationOptions1State);
impl_ipv6_encapsulated!(DestinationOptions1State);
impl_routing_header!(DestinationOptions1State);

// RoutingHeader
impl_tcp!(RoutingHeaderState, &[u8; 16]);
impl_udp!(RoutingHeaderState, &[u8; 16]);
impl_icmpv6!(RoutingHeaderState, &[u8; 16]);
impl_ipv4_encapsulated!(RoutingHeaderState);
impl_ipv6_encapsulated!(RoutingHeaderState);
impl_fragment_header!(RoutingHeaderState);
impl_authentication_header!(RoutingHeaderState);
impl_destination_options_2!(RoutingHeaderState);

// FragmentHeader
impl_tcp!(FragmentHeaderState, &[u8; 16]);
impl_udp!(FragmentHeaderState, &[u8; 16]);
impl_icmpv6!(FragmentHeaderState, &[u8; 16]);
impl_ipv4_encapsulated!(FragmentHeaderState);
impl_ipv6_encapsulated!(FragmentHeaderState);
impl_authentication_header!(FragmentHeaderState);
impl_destination_options_2!(FragmentHeaderState);

// AuthHeader
impl_tcp!(AuthHeaderState, &[u8; 16]);
impl_udp!(AuthHeaderState, &[u8; 16]);
impl_icmpv6!(AuthHeaderState, &[u8; 16]);
impl_ipv4_encapsulated!(AuthHeaderState);
impl_ipv6_encapsulated!(AuthHeaderState);
impl_destination_options_2!(AuthHeaderState);

// DestinationOptions2
impl_tcp!(DestinationOptions2State, &[u8; 16]);
impl_udp!(DestinationOptions2State, &[u8; 16]);
impl_icmpv6!(DestinationOptions2State, &[u8; 16]);
impl_ipv4_encapsulated!(DestinationOptions2State);
impl_ipv6_encapsulated!(DestinationOptions2State);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datalink::arp::ARP_HEADER_LENGTH, misc::IpInIp, network::ipv4::IPV4_MIN_HEADER_LENGTH,
        packet::parser::PacketParser, transport::udp::UDP_HEADER_LENGTH,
    };

    #[test]
    fn write_payload() {
        // Raw packet data.
        let mut buffer = [0u8; 64];

        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Construct PacketBuilder with an Ethernet header, an IPv4 header, a UDP header, and a payload.
        let packet_builder = PacketBuilder::new(&mut buffer)
            // 14 bytes
            .ethernet(&[1, 2, 3, 4, 5, 6], &[7, 8, 9, 10, 11, 12], 0x0800)
            .unwrap()
            // 20 bytes
            .ipv4(
                4,
                5,
                0,
                0,
                50,
                0,
                0,
                0,
                64,
                17,
                &[192, 168, 1, 1],
                &[192, 168, 1, 2],
            )
            .unwrap()
            // 8 bytes + 10 bytes
            .udp(
                &[192, 168, 1, 1],
                12345,
                &[192, 168, 1, 2],
                54321,
                30,
                Some(&payload),
            )
            .unwrap();

        // Ensure the header length is correct.
        assert_eq!(
            packet_builder.header_len(),
            ETHERNET_MIN_HEADER_LENGTH + IPV4_MIN_HEADER_LENGTH + UDP_HEADER_LENGTH
        );

        // Ensure the payload is correct.
        assert_eq!(
            packet_builder.payload(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        // Build the packet.
        let packet = packet_builder.build();

        // Parse the packet.
        let parser = PacketParser::parse(&packet);

        // Ensure the parser succeeded.
        assert!(parser.is_ok());

        // Unwrap the parser.
        let parser = parser.unwrap();

        // Ensure the parser contains an UDP header.
        assert!(parser.udp.is_some());

        // Unwrap the UDP header.
        let udp = parser.udp.unwrap();

        // Ensure the payload is correct.
        assert_eq!(
            udp.payload(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn misc() {
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
    fn arp_in_ethernet() {
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
    fn tcp_in_ipv4_in_ethernet() {
        // Raw packet data.
        let mut packet = [0u8; 54];

        // Expected output given the chosen values.
        let should_be = [
            4, 180, 254, 154, 129, 199, 52, 151, 246, 148, 2, 15, 8, 0, 53, 143, 48, 57, 212, 49,
            112, 57, 123, 6, 87, 113, 192, 168, 1, 1, 192, 168, 1, 2, 0, 99, 0, 11, 0, 0, 0, 123,
            0, 0, 1, 65, 179, 99, 16, 225, 177, 80, 4, 210,
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
                    None,
                )
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn udp_in_ipv4_in_ethernet() {
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
                .udp(&[192, 168, 1, 1], 99, &[192, 168, 1, 2], 11, 4321, None)
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn icmpv4_in_ipv4_in_ethernet() {
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
                .icmpv4(8, 0, None)
                .unwrap();
        });

        // Output should match the expectation.
        assert_eq!(packet, should_be);

        // Ensure zero allocations.
        assert_eq!(allocations.count_total, 0);
    }

    #[test]
    fn build_parse_ipv6() {
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
            .udp(&src_addr, 99, &dest_addr, 80, 10, None)
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
    fn build_parse_qinq() {
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
            .udp(&[192, 168, 1, 1], 99, &[192, 168, 1, 2], 11, 22, None)
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
    fn build_parse_qinq_icmpv6() {
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
            .icmpv6(&src_addr, &dest_addr, 128, 0, None)
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

    #[test]
    pub fn build_parse_very_complex_packet() {
        // Raw packet data.
        let mut buffer = [0u8; 300];

        // Build the packet.
        let packet = PacketBuilder::new(&mut buffer)
            .ethernet_qinq(
                &[0x34, 0x97, 0xf6, 0x94, 0x02, 0x0f],
                &[0x04, 0xb4, 0xfe, 0x9a, 0x81, 0xc7],
                34525,
                200,
                100,
            )
            .unwrap()
            .ipv6(6, 5, 4, 3, 0, 255, &[0; 16], &[0; 16])
            .unwrap()
            .hop_by_hop(60, 1, &[1; 8])
            .unwrap()
            .destination_options1(43, 1, &[1; 8])
            .unwrap()
            .routing_header(44, 1, 2, 3, &[2; 8])
            .unwrap()
            .fragment_header(51, 255, true, 0x04050607)
            .unwrap()
            .authentication_header(60, 2, 305419896, 2271560481, &[1; 8])
            .unwrap()
            .destination_options2(4, 1, &[1; 8])
            .unwrap()
            .ipv4(
                4,
                5,
                0,
                0,
                150,
                0,
                0,
                0,
                64,
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
                Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            )
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
        assert!(unwrapped.ip_in_ip.is_some());
        assert!(unwrapped.tcp.is_some());

        // Ensure the unexpected headers are not present.
        assert!(unwrapped.arp.is_none());
        assert!(unwrapped.udp.is_none());
        assert!(unwrapped.icmpv4.is_none());
        assert!(unwrapped.icmpv6.is_none());

        // Unwrap IPv6.
        let ipv6 = unwrapped.ipv6.unwrap();

        // Ensure extension headers are present.
        assert!(ipv6.extension_headers.is_some());

        // Unwrap the extension headers.
        let extensions = ipv6.extension_headers.unwrap();

        // Ensure the expected extension headers are present.
        assert!(extensions.hop_by_hop.is_some());
        assert!(extensions.destination_1st.is_some());
        assert!(extensions.routing.is_some());
        assert!(extensions.fragment.is_some());
        assert!(extensions.auth_header.is_some());
        assert!(extensions.destination_2nd.is_some());

        // Unwrap the IP-in-IP.
        let ip_in_ip = unwrapped.ip_in_ip.unwrap();

        // Ensure the expected headers are present.
        assert!(match ip_in_ip {
            IpInIp::Ipv4(_) => true,
            _ => false,
        });
    }
}
