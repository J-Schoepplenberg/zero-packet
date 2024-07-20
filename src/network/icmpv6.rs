use super::checksum::internet_checksum;
use core::fmt;

/// The length of an ICMPv6 header in bytes.
pub const ICMPV6_HEADER_LENGTH: usize = 8;

/// Writes ICMPv6 header fields.
pub struct Icmpv6Writer<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> Icmpv6Writer<'a> {
    /// Creates a new `Icmpv6Writer` from the given slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ICMPV6_HEADER_LENGTH {
            return Err("Slice is too short to contain an ICMP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ICMPV6_HEADER_LENGTH
    }

    /// Returns the total length of the packet in bytes.
    #[inline]
    pub fn packet_len(&self) -> usize {
        self.bytes.len()
    }

    /// Sets the type field.
    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        self.bytes[0] = icmp_type;
    }

    /// Sets the code field.
    #[inline]
    pub fn set_icmp_code(&mut self, icmp_code: u8) {
        self.bytes[1] = icmp_code;
    }

    /// Sets the payload field.
    ///
    /// The `PacketBuilder` sets the payload before the checksum.
    ///
    /// That is, because the checksum is invalidated if a payload is set after it.
    #[inline]
    pub fn set_payload(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        let start = self.header_len();
        let payload_len = payload.len();

        if self.packet_len() - start < payload_len {
            return Err("Payload is too large to fit in the ICMPv6 packet.");
        }

        let end = start + payload_len;
        self.bytes[start..end].copy_from_slice(payload);

        Ok(())
    }

    /// Calculates the internet checksum for error checking.
    ///
    /// Includes the ICMPv6 header, payload and IPv6 pseudo header.
    #[inline]
    pub fn set_checksum(&mut self, pseudo_sum: u32) {
        self.bytes[2] = 0;
        self.bytes[3] = 0;
        let checksum = internet_checksum(self.bytes, pseudo_sum);
        self.bytes[2] = (checksum >> 8) as u8;
        self.bytes[3] = (checksum & 0xff) as u8;
    }
}

/// Reads an ICMPv6 header.
#[derive(PartialEq)]
pub struct Icmpv6Reader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> Icmpv6Reader<'a> {
    /// Creates a new `Icmpv6Reader` from the given slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ICMPV6_HEADER_LENGTH {
            return Err("Slice is too short to contain an ICMP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the type field.
    #[inline]
    pub fn icmp_type(&self) -> u8 {
        self.bytes[0]
    }

    /// Returns the code field.
    #[inline]
    pub fn icmp_code(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        ((self.bytes[2] as u16) << 8) | (self.bytes[3] as u16)
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ICMPV6_HEADER_LENGTH
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..ICMPV6_HEADER_LENGTH]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[ICMPV6_HEADER_LENGTH..]
    }
}

impl fmt::Debug for Icmpv6Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Icmpv6Packet")
            .field("icmp_type", &self.icmp_type())
            .field("icmp_code", &self.icmp_code())
            .field("checksum", &self.checksum())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::checksum::pseudo_header;

    #[test]
    fn getters_and_setters() {
        // Raw packet.
        let mut bytes = [0; ICMPV6_HEADER_LENGTH];

        // Random values.
        let icmp_type = 8;
        let icmp_code = 0;

        // Pseudo header.
        let src_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];
        let dest_addr = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0xb3, 0xff, 0xfe, 0x1e,
            0x83, 0x29,
        ];
        let protocol = 58;
        let length = 8;

        // Create a ICMPv6 writer.
        let mut writer = Icmpv6Writer::new(&mut bytes).unwrap();

        // Set the values.
        writer.set_icmp_type(icmp_type);
        writer.set_icmp_code(icmp_code);

        // Set the checksum including the pseudo header.
        let pseudo_sum = pseudo_header(&src_addr, &dest_addr, protocol, length);
        writer.set_checksum(pseudo_sum);

        // Create a ICMPv6 reader.
        let reader = Icmpv6Reader::new(&bytes).unwrap();

        // Check the values.
        assert_eq!(reader.icmp_type(), icmp_type);
        assert_eq!(reader.icmp_code(), icmp_code);
    }
}
