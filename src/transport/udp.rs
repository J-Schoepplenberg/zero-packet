use crate::network::checksum::{internet_checksum, pseudo_header};
use core::fmt;

/// Represents a UDP packet.
pub struct UdpDatagram<'a> {
    pub data: &'a mut [u8],
}

impl<'a> UdpDatagram<'a> {
    /// The minimum length of a UDP header in bytes.
    pub const HEADER_LENGTH: usize = 8;

    /// Creates a new `UdpPacket` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < Self::HEADER_LENGTH {
            return Err("Slice is too short to contain a UDP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        Self::HEADER_LENGTH
    }

    /// Returns the source port field.
    #[inline]
    pub fn get_src_port(&self) -> u16 {
        ((self.data[0] as u16) << 8) | (self.data[1] as u16)
    }

    /// Returns the destination port field.
    #[inline]
    pub fn get_dest_port(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }

    /// Returns the length field.
    #[inline]
    pub fn get_length(&self) -> u16 {
        ((self.data[4] as u16) << 8) | (self.data[5] as u16)
    }

    /// Sets the source port field.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.data[0] = (src_port >> 8) as u8;
        self.data[1] = src_port as u8;
    }

    /// Sets the destination port field.
    #[inline]
    pub fn set_dest_port(&mut self, dst_port: u16) {
        self.data[2] = (dst_port >> 8) as u8;
        self.data[3] = dst_port as u8;
    }

    /// Sets the length field.
    #[inline]
    pub fn set_length(&mut self, length: u16) {
        self.data[4] = (length >> 8) as u8;
        self.data[5] = length as u8;
    }

    /// Calculates the checksum field for error checking.
    ///
    /// Consists of the IP pseudo-header, TCP header and payload.
    ///
    /// Checksum is optional in UDP for IPv4, but mandatory for IPv6.
    /// Although, it is strongly recommended to use checksums for both. See: RFC 1122.
    #[inline]
    pub fn set_checksum(&mut self, src_ip: &[u8; 4], dest_ip: &[u8; 4]) {
        self.data[6] = 0;
        self.data[7] = 0;
        let pseudo_header = pseudo_header(src_ip, dest_ip, 17, self.data.len());
        let checksum = internet_checksum(&self.data, pseudo_header);
        self.data[6] = (checksum >> 8) as u8;
        self.data[7] = (checksum & 0xff) as u8;
    }
}

impl fmt::Debug for UdpDatagram<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpDatagram")
            .field("src_port", &self.get_src_port())
            .field("dest_port", &self.get_dest_port())
            .field("length", &self.get_length())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet data.
        let mut data = [0u8; 8];

        // Random values.
        let src_port = 12345;
        let dst_port = 54321;
        let length = 8;
        let src_ip = [192, 168, 1, 1];
        let dest_ip = [192, 168, 1, 2];

        // Create a new UDP datagram from the raw data.
        let mut udp_datagram = UdpDatagram::new(&mut data).unwrap();

        // Set the fields.
        udp_datagram.set_src_port(src_port);
        udp_datagram.set_dest_port(dst_port);
        udp_datagram.set_length(length);
        udp_datagram.set_checksum(&src_ip, &dest_ip);

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(udp_datagram.get_src_port(), src_port);
        assert_eq!(udp_datagram.get_dest_port(), dst_port);
        assert_eq!(udp_datagram.get_length(), length);
    }
}
