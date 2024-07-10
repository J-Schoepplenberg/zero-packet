use super::checksum::internet_checksum;
use core::fmt;

/// The length of an ICMP header in bytes.
pub const ICMP_HEADER_LENGTH: usize = 8;

/// The maximum valid ICMP type.
pub const ICMP_MAX_VALID_CODE: u8 = 15;

/// Represents an ICMP header.
pub struct IcmpWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> IcmpWriter<'a> {
    /// Creates a new `Icmp` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ICMP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ICMP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ICMP_HEADER_LENGTH
    }

    /// Returns the identifier field.
    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        self.bytes[0] = icmp_type;
    }

    /// Sets the code field.
    #[inline]
    pub fn set_icmp_code(&mut self, code: u8) {
        self.bytes[1] = code;
    }

    /// Calculates the internet checksum (RFC 1071) for error checking.
    ///
    /// Includes the ICMP header and payload.
    #[inline]
    pub fn set_checksum(&mut self) {
        self.bytes[2] = 0;
        self.bytes[3] = 0;
        let checksum = internet_checksum(self.bytes, 0);
        self.bytes[2] = (checksum >> 8) as u8;
        self.bytes[3] = (checksum & 0xff) as u8;
    }
}

#[derive(PartialEq)]
pub struct IcmpReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> IcmpReader<'a> {
    /// Creates a new `Icmp` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ICMP_HEADER_LENGTH {
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
        ICMP_HEADER_LENGTH
    }

    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..ICMP_HEADER_LENGTH]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[ICMP_HEADER_LENGTH..]
    }
}

impl fmt::Debug for IcmpReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcmpPacket")
            .field("type", &self.icmp_type())
            .field("code", &self.icmp_code())
            .field("checksum", &self.checksum())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 8];

        // Random values.
        let icmp_type = 8;
        let code = 0;

        // Create a ICMP writer.
        let mut writer = IcmpWriter::new(&mut bytes).unwrap();

        // Set the values.
        writer.set_icmp_type(icmp_type);
        writer.set_icmp_code(code);
        writer.set_checksum();

        // Create a ICMP reader.
        let reader = IcmpReader::new(&bytes).unwrap();

        // Check the values.
        assert_eq!(reader.icmp_type(), icmp_type);
        assert_eq!(reader.icmp_code(), code);
    }
}
