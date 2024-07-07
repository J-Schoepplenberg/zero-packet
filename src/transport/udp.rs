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
            return Err("Slice is too short to be a UDP header.");
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

    /// Calculates the checksum field.
    /// See: https://datatracker.ietf.org/doc/html/rfc1071.
    #[inline]
    pub fn set_checksum(&mut self, src_ip: &[u8; 4], dest_ip: &[u8; 4]) {
        self.data[6] = 0;
        self.data[7] = 0;

        let mut count = self.data.len();
        let mut sum = 0;
        let mut i = 0;

        sum += ((src_ip[0] as u32) << 8) + (src_ip[1] as u32);
        sum += ((src_ip[2] as u32) << 8) + (src_ip[3] as u32);
        sum += ((dest_ip[0] as u32) << 8) + (dest_ip[1] as u32);
        sum += ((dest_ip[2] as u32) << 8) + (dest_ip[3] as u32);
        sum += 17; 
        sum += count as u32;

        while count > 1 {
            sum += ((self.data[i] as u32) << 8) + (self.data[i + 1] as u32);
            count -= 2;
            i += 2;
        }

        if count > 0 {
            sum += (self.data[i] as u32) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !sum as u16;

        self.data[6] = (checksum >> 8) as u8;
        self.data[7] = (checksum & 0xff) as u8;
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