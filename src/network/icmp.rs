use super::checksum::internet_checksum;
use core::fmt;

/// The length of an ICMP header in bytes.
pub const ICMP_HEADER_LENGTH: usize = 8;

/// The maximum valid ICMP type.
pub const ICMP_MAX_VALID_CODE: u8 = 15;

/// Represents an ICMP header.
pub struct IcmpBuilder<'a> {
    pub data: &'a mut [u8],
}

impl<'a> IcmpBuilder<'a> {
    /// Creates a new `Icmp` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < ICMP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ICMP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        ICMP_HEADER_LENGTH
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

#[derive(PartialEq)]
pub struct IcmpParser<'a> {
    pub data: &'a [u8],
}

impl<'a> IcmpParser<'a> {
    /// Creates a new `Icmp` from the given data slice.
    #[inline]
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < ICMP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ICMP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        ICMP_HEADER_LENGTH
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

    #[inline]
    pub fn get_header(&self) -> &'a [u8] {
        &self.data[..ICMP_HEADER_LENGTH]
    }

    #[inline]
    pub fn get_payload(&self) -> &'a [u8] {
        &self.data[ICMP_HEADER_LENGTH..]
    }
}

impl fmt::Debug for IcmpParser<'_> {
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

        // Create a IcmpBuilder.
        let mut builder = IcmpBuilder::new(&mut data).unwrap();

        // Set the values.
        builder.set_type(icmp_type);
        builder.set_code(code);
        builder.set_checksum();

        // Create a IcmpParser.
        let parser = IcmpParser::new(&data).unwrap();

        // Check the values.
        assert_eq!(parser.get_type(), icmp_type);
        assert_eq!(parser.get_code(), code);
    }
}
