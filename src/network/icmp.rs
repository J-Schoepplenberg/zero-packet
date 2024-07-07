use super::checksum::internet_checksum;
use core::fmt;

/// Represents an ICMP header.
pub struct IcmpPacket<'a> {
    pub data: &'a mut [u8],
}

impl<'a> IcmpPacket<'a> {
    /// The minimum length of an ICMP header in bytes.
    const HEADER_LENGTH: usize = 8;

    /// Creates a new `Icmp` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < Self::HEADER_LENGTH {
            return Err("Slice is too short to contain an ICMP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        Self::HEADER_LENGTH
    }

    /// Returns the type field.
    #[inline]
    pub fn get_type(&self) -> u8 {
        self.data[0]
    }

    /// Returns the code field.
    #[inline]
    pub fn get_code(&self) -> u8 {
        self.data[1]
    }

    /// Returns the checksum field.
    #[inline]
    pub fn get_checksum(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }

    /// Returns the identifier field.
    #[inline]
    pub fn set_type(&mut self, icmp_type: u8) {
        self.data[0] = icmp_type;
    }

    /// Sets the code field.
    #[inline]
    pub fn set_code(&mut self, code: u8) {
        self.data[1] = code;
    }

    /// Calculates the internet checksum (RFC 1071) for error checking.
    ///
    /// Includes the ICMP header and payload.
    #[inline]
    pub fn set_checksum(&mut self) {
        self.data[2] = 0;
        self.data[3] = 0;
        let checksum = internet_checksum(self.data, 0);
        self.data[2] = (checksum >> 8) as u8;
        self.data[3] = (checksum & 0xff) as u8;
    }
}

impl fmt::Debug for IcmpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcmpPacket")
            .field("type", &self.get_type())
            .field("code", &self.get_code())
            .field("checksum", &self.get_checksum())
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
        let icmp_type = 8;
        let code = 0;

        // Create a new ICMP packet.
        let mut icmp = IcmpPacket::new(&mut data).unwrap();
        icmp.set_type(icmp_type);
        icmp.set_code(code);
        icmp.set_checksum();

        // Check the values.
        assert_eq!(icmp.get_type(), icmp_type);
        assert_eq!(icmp.get_code(), code);
    }
}
