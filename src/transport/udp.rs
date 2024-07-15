use crate::network::checksum::internet_checksum;
use core::fmt;

/// The length of a UDP header in bytes.
pub const UDP_HEADER_LENGTH: usize = 8;

/// Writes UDP header fields.
pub struct UdpWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> UdpWriter<'a> {
    /// Creates a new `UdpPacket` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < UDP_HEADER_LENGTH {
            return Err("Slice is too short to contain a UDP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        UDP_HEADER_LENGTH
    }

    /// Returns the total length of the packet in bytes.
    #[inline]
    pub fn packet_len(&self) -> usize {
        self.bytes.len()
    }

    /// Sets the source port field.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.bytes[0] = (src_port >> 8) as u8;
        self.bytes[1] = src_port as u8;
    }

    /// Sets the destination port field.
    #[inline]
    pub fn set_dest_port(&mut self, dst_port: u16) {
        self.bytes[2] = (dst_port >> 8) as u8;
        self.bytes[3] = dst_port as u8;
    }

    /// Sets the length field.
    ///
    /// Should include the entire packet (header and payload).
    #[inline]
    pub fn set_length(&mut self, length: u16) {
        self.bytes[4] = (length >> 8) as u8;
        self.bytes[5] = length as u8;
    }

    /// Calculates the checksum field for error checking.
    ///
    /// Includes the UDP header, payload and IPv4 pseudo header.
    ///
    /// Checksum is optional in UDP for IPv4, but mandatory for IPv6.
    /// Although, it is strongly recommended to use checksums for both. See: RFC 1122.
    #[inline]
    pub fn set_checksum(&mut self, pseudo_sum: u32) {
        self.bytes[6] = 0;
        self.bytes[7] = 0;
        let checksum = internet_checksum(self.bytes, pseudo_sum);
        self.bytes[6] = (checksum >> 8) as u8;
        self.bytes[7] = (checksum & 0xff) as u8;
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
            return Err("Payload is too large to fit in the TCP packet.");
        }
        
        let end = start + payload_len;
        self.bytes[start..end].copy_from_slice(payload);

        Ok(())
    }
}

/// Reads UDP header fields.
#[derive(PartialEq)]
pub struct UdpReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> UdpReader<'a> {
    /// Creates a new `UdpPacket` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < UDP_HEADER_LENGTH {
            return Err("Slice is too short to contain a UDP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the source port field.
    #[inline]
    pub fn src_port(&self) -> u16 {
        ((self.bytes[0] as u16) << 8) | (self.bytes[1] as u16)
    }

    /// Returns the destination port field.
    #[inline]
    pub fn dest_port(&self) -> u16 {
        ((self.bytes[2] as u16) << 8) | (self.bytes[3] as u16)
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        ((self.bytes[6] as u16) << 8) | (self.bytes[7] as u16)
    }

    /// Returns the length field.
    ///
    /// Includes the entire packet (header and payload).
    #[inline]
    pub fn length(&self) -> u16 {
        ((self.bytes[4] as u16) << 8) | (self.bytes[5] as u16)
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        UDP_HEADER_LENGTH
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..UDP_HEADER_LENGTH]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[UDP_HEADER_LENGTH..]
    }
}

impl fmt::Debug for UdpReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpDatagram")
            .field("src_port", &self.src_port())
            .field("dest_port", &self.dest_port())
            .field("length", &self.length())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::checksum::ipv4_pseudo_header;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 8];

        // Random values.
        let src_port = 12345;
        let dst_port = 54321;
        let length = 8;
        let src_ip = [192, 168, 1, 1];
        let dest_ip = [192, 168, 1, 2];

        // Create a UDP packet writer.
        let mut writer = UdpWriter::new(&mut bytes).unwrap();

        // Set the fields.
        writer.set_src_port(src_port);
        writer.set_dest_port(dst_port);
        writer.set_length(length);

        // Calculate the checksum.
        let pseudo_sum = ipv4_pseudo_header(&src_ip, &dest_ip, 17, writer.packet_len());
        writer.set_checksum(pseudo_sum);

        // Create a UDP packet reader.
        let reader = UdpReader::new(&bytes).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(reader.src_port(), src_port);
        assert_eq!(reader.dest_port(), dst_port);
        assert_eq!(reader.length(), length);
    }
}
