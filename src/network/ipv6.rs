use crate::misc::bytes_to_ipv6;
use core::{fmt, str::from_utf8};

/// The length of an IPv6 header in bytes.
pub const IPV6_HEADER_LEN: usize = 40;

/// Writes IPv6 header fields.
pub struct IPv6Writer<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> IPv6Writer<'a> {
    /// Creates a new `IPv6Writer` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < IPV6_HEADER_LEN {
            return Err("Slice is too short to contain an IPv6 header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the actual header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        IPV6_HEADER_LEN
    }

    /// Sets the version field.
    ///
    /// Indicates the IP version number. Should be set to 6.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.bytes[0] = (self.bytes[0] & 0x0F) | (version << 4);
    }

    /// Sets the traffic class field.
    ///
    /// Specifies the priority of the packet.
    #[inline]
    pub fn set_traffic_class(&mut self, traffic_class: u8) {
        self.bytes[0] = (self.bytes[0] & 0xF0) | (traffic_class >> 4);
        self.bytes[1] = (self.bytes[1] & 0x0F) | (traffic_class << 4);
    }

    /// Sets the flow label field.
    ///
    /// Identifies packets belonging to the same flow (group of packets).
    #[inline]
    pub fn set_flow_label(&mut self, flow_label: u32) {
        self.bytes[1] = (self.bytes[1] & 0xF0) | ((flow_label >> 16) as u8);
        self.bytes[2] = (flow_label >> 8) as u8;
        self.bytes[3] = flow_label as u8;
    }

    /// Sets the payload length field.
    ///
    /// Specifies the length of the payload in bytes.
    #[inline]
    pub fn set_payload_length(&mut self, payload_length: u16) {
        self.bytes[4] = (payload_length >> 8) as u8;
        self.bytes[5] = payload_length as u8;
    }

    /// Sets the next header field.
    ///
    /// Specifies the type of the next header, usually a transport protocol.
    ///
    /// Shares the same values as the protocol field in an IPv4 header.
    #[inline]
    pub fn set_next_header(&mut self, next_header: u8) {
        self.bytes[6] = next_header;
    }

    /// Sets the hop limit field.
    ///
    /// Replaces the time-to-live field in IPv4.
    ///
    /// The value is decremented each time the packet is forwarded by a router.
    ///
    /// When the value reaches 0, the packet is discarded, unless it has reached its destination.
    #[inline]
    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        self.bytes[7] = hop_limit;
    }

    /// Sets the source address field.
    ///
    /// Unicast IPv6 address of the sender.
    #[inline]
    pub fn set_src_addr(&mut self, src_addr: &[u8; 16]) {
        self.bytes[8] = src_addr[0];
        self.bytes[9] = src_addr[1];
        self.bytes[10] = src_addr[2];
        self.bytes[11] = src_addr[3];
        self.bytes[12] = src_addr[4];
        self.bytes[13] = src_addr[5];
        self.bytes[14] = src_addr[6];
        self.bytes[15] = src_addr[7];
        self.bytes[16] = src_addr[8];
        self.bytes[17] = src_addr[9];
        self.bytes[18] = src_addr[10];
        self.bytes[19] = src_addr[11];
        self.bytes[20] = src_addr[12];
        self.bytes[21] = src_addr[13];
        self.bytes[22] = src_addr[14];
        self.bytes[23] = src_addr[15];
    }

    /// Sets the destination address field.
    ///
    /// Unicast or multicast IPv6 address of the intended recipient.
    #[inline]
    pub fn set_dest_addr(&mut self, dest_addr: &[u8; 16]) {
        self.bytes[24] = dest_addr[0];
        self.bytes[25] = dest_addr[1];
        self.bytes[26] = dest_addr[2];
        self.bytes[27] = dest_addr[3];
        self.bytes[28] = dest_addr[4];
        self.bytes[29] = dest_addr[5];
        self.bytes[30] = dest_addr[6];
        self.bytes[31] = dest_addr[7];
        self.bytes[32] = dest_addr[8];
        self.bytes[33] = dest_addr[9];
        self.bytes[34] = dest_addr[10];
        self.bytes[35] = dest_addr[11];
        self.bytes[36] = dest_addr[12];
        self.bytes[37] = dest_addr[13];
        self.bytes[38] = dest_addr[14];
        self.bytes[39] = dest_addr[15];
    }
}

/// Reads IPv6 header fields.
pub struct IPv6Reader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> IPv6Reader<'a> {
    /// Creates a new `IPv6Reader` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < IPV6_HEADER_LEN {
            return Err("Slice is too short to contain an IPv6 header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the version field.
    ///
    /// Indicates the IP version number. Should be set to 6.
    #[inline]
    pub fn version(&self) -> u8 {
        self.bytes[0] >> 4
    }

    /// Returns the traffic class field.
    ///
    /// Specifies the priority of the packet.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.bytes[0] & 0x0F) << 4) | (self.bytes[1] >> 4)
    }

    /// Returns the flow label field.
    ///
    /// Identifies packets belonging to the same flow (group of packets).
    #[inline]
    pub fn flow_label(&self) -> u32 {
        ((self.bytes[1] as u32 & 0x0F) << 16)
            | ((self.bytes[2] as u32) << 8)
            | (self.bytes[3] as u32)
    }

    /// Returns the payload length field.
    ///
    /// Specifies the length of the payload in bytes.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        ((self.bytes[4] as u16) << 8) | (self.bytes[5] as u16)
    }

    /// Returns the next header field.
    ///
    /// Specifies the type of the next header, usually a transport protocol.
    ///
    /// Shares the same values as the protocol field in an IPv4 header.
    #[inline]
    pub fn next_header(&self) -> u8 {
        self.bytes[6]
    }

    /// Returns the hop limit field.
    ///
    /// Replaces the time-to-live field in IPv4.
    ///
    /// The value is decremented each time the packet is forwarded by a router.
    ///
    /// When the value reaches 0, the packet is discarded, unless it has reached its destination.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    /// Returns the source address field.
    ///
    /// Unicast IPv6 address of the sender.
    #[inline]
    pub fn src_addr(&self) -> &[u8] {
        &self.bytes[8..24]
    }

    /// Returns the destination address field.
    ///
    /// Unicast or multicast IPv6 address of the intended recipient.
    #[inline]
    pub fn dest_addr(&self) -> &[u8] {
        &self.bytes[24..40]
    }

    /// Returns the actual header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        IPV6_HEADER_LEN
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..self.header_len()]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len()..]
    }
}

impl<'a> fmt::Debug for IPv6Reader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s_buf = [0u8; 39];
        let s_len = bytes_to_ipv6(self.src_addr(), &mut s_buf);
        let s_hex = from_utf8(&s_buf[..s_len]).unwrap();
        let mut d_buf = [0u8; 39];
        let d_len = bytes_to_ipv6(self.dest_addr(), &mut d_buf);
        let d_hex = from_utf8(&d_buf[..d_len]).unwrap();
        f.debug_struct("IPv6Packet")
            .field("version", &self.version())
            .field("traffic_class", &self.traffic_class())
            .field("flow_label", &self.flow_label())
            .field("payload_length", &self.payload_length())
            .field("next_header", &self.next_header())
            .field("hop_limit", &self.hop_limit())
            .field("src_addr", &s_hex)
            .field("dest_addr", &d_hex)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 40];

        // Random values.
        let version = 6;
        let traffic_class = 5;
        let flow_label = 4;
        let payload_length = 3;
        let next_header = 2;
        let hop_limit = 1;
        let src_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];
        let dest_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x83, 0xa3, 0x00, 0x00, 0x50, 0x00, 0x81, 0x2e, 0x03, 0x70,
            0x73, 0x32,
        ];

        // Create a IPv6 packet writer.
        let mut writer = IPv6Writer::new(&mut bytes).unwrap();

        // Set the fields.
        writer.set_version(version);
        writer.set_traffic_class(traffic_class);
        writer.set_flow_label(flow_label);
        writer.set_payload_length(payload_length);
        writer.set_next_header(next_header);
        writer.set_hop_limit(hop_limit);
        writer.set_src_addr(&src_addr);
        writer.set_dest_addr(&dest_addr);

        // Create a IPv6 packet reader.
        let reader = IPv6Reader::new(&bytes).unwrap();

        // Check the fields.
        assert_eq!(reader.version(), version);
        assert_eq!(reader.traffic_class(), traffic_class);
        assert_eq!(reader.flow_label(), flow_label);
        assert_eq!(reader.payload_length(), payload_length);
        assert_eq!(reader.next_header(), next_header);
        assert_eq!(reader.hop_limit(), hop_limit);
        assert_eq!(reader.src_addr(), &src_addr);
        assert_eq!(reader.dest_addr(), &dest_addr);
    }
}
