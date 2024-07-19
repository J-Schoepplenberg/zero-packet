use core::fmt;

/// The minimum length of an Authentication Header.
pub const AUTHENTICATION_MIN_HEADER_LENGTH: usize = 12;

/// Writes the Authentication Header fields.
pub struct AuthenticationHeaderWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> AuthenticationHeaderWriter<'a> {
    /// Creates a new `AuthenticationHeaderWriter` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < AUTHENTICATION_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Authentication extension header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the total header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[1] as usize + 2) * 4
    }

    /// Sets the next header field.
    ///
    /// Identifies the type of the next header.
    #[inline]
    pub fn set_next_header(&mut self, next_header: u8) {
        self.bytes[0] = next_header;
    }

    /// Sets the payload length field.
    ///
    /// Length of this Authentication Header with scaling factor of 4, minus 2.
    ///
    /// E.g: Header length = (payload_len + 2) * 4.
    #[inline]
    pub fn set_payload_len(&mut self, payload_len: u8) {
        self.bytes[1] = payload_len;
    }

    /// Sets the reserved field.
    ///
    /// Should be all zeros.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u16) {
        self.bytes[2] = (reserved >> 8) as u8;
        self.bytes[3] = reserved as u8;
    }

    /// Sets the Security Parameters Index field.
    ///
    /// Arbitrary value which is used (together with the destination IP address) to identify the security association of the receiving party.
    #[inline]
    pub fn set_spi(&mut self, spi: u32) {
        self.bytes[4] = (spi >> 24) as u8;
        self.bytes[5] = (spi >> 16) as u8;
        self.bytes[6] = (spi >> 8) as u8;
        self.bytes[7] = spi as u8;
    }

    /// Sets the sequence number field.
    ///
    /// Monotonically increasing counter value to prevent replay attacks.
    #[inline]
    pub fn set_sequence_number(&mut self, sequence_number: u32) {
        self.bytes[8] = (sequence_number >> 24) as u8;
        self.bytes[9] = (sequence_number >> 16) as u8;
        self.bytes[10] = (sequence_number >> 8) as u8;
        self.bytes[11] = sequence_number as u8;
    }

    /// Sets the authentication data field.
    ///
    /// Padding:
    /// - 4-octet alignment for IPv4 packets.
    /// - 8-octet alignment for IPv6 packets.
    #[inline]
    pub fn set_authentication_data(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let start_offset = 12;
        let end_offset = start_offset + data.len();

        if end_offset > self.bytes.len() {
            return Err("Authentication data exceeds the allocated header length.");
        }

        self.bytes[start_offset..end_offset].copy_from_slice(data);

        Ok(())
    }
}

/// Reads the Authentication extension header fields.
pub struct AuthenticationHeaderReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> AuthenticationHeaderReader<'a> {
    /// Creates a new `AuthenticationHeaderReader` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < AUTHENTICATION_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Authentication extension header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the next header field.
    ///
    /// Specifies the type of the next header.
    #[inline]
    pub fn next_header(&self) -> u8 {
        self.bytes[0]
    }

    /// Returns the payload length field.
    ///
    /// Length of the payload in 32-bit words, minus 2.
    #[inline]
    pub fn payload_len(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the reserved field.
    ///
    /// Should be all zeroes.
    #[inline]
    pub fn reserved(&self) -> u16 {
        ((self.bytes[2] as u16) << 8) | self.bytes[3] as u16
    }

    /// Returns the Security Parameters Index field.
    ///
    /// Arbitrary value which is used (together with the destination IP address) to identify the security association of the receiving party.
    #[inline]
    pub fn spi(&self) -> u32 {
        ((self.bytes[4] as u32) << 24)
            | ((self.bytes[5] as u32) << 16)
            | ((self.bytes[6] as u32) << 8)
            | self.bytes[7] as u32
    }

    /// Returns the sequence number field.
    ///
    /// Monotonically increasing counter value to prevent replay attacks.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        ((self.bytes[8] as u32) << 24)
            | ((self.bytes[9] as u32) << 16)
            | ((self.bytes[10] as u32) << 8)
            | self.bytes[11] as u32
    }

    /// Returns the authentication data field.
    ///
    /// Variable-length field.
    #[inline]
    pub fn authentication_data(&self) -> Result<&'a [u8], &'static str> {
        if self.bytes.len() < self.header_len() {
            return Err("Indicated Authentication header length exceeds the allocated buffer.");
        }

        Ok(&self.bytes[12..self.header_len()])
    }

    /// Returns the total header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[1] as usize + 2) * 4
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> Result<&'a [u8], &'static str> {
        let end = self.header_len();

        if end > self.bytes.len() {
            return Err("Indicated Authentication header length exceeds the allocated buffer.");
        }

        Ok(&self.bytes[..end])
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> Result<&'a [u8], &'static str> {
        let start = self.header_len();

        if start > self.bytes.len() {
            return Err("Indicated Authentication header length exceeds the allocated buffer.");
        }

        Ok(&self.bytes[self.header_len()..])
    }
}

impl fmt::Debug for AuthenticationHeaderReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationHeader")
            .field("next_header", &self.next_header())
            .field("payload_len", &self.payload_len())
            .field("reserved", &self.reserved())
            .field("spi", &self.spi())
            .field("sequence_number", &self.sequence_number())
            .field("authentication_data", &self.authentication_data())
            .finish()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0; 20];

        // Random values.
        let next_header = 17;
        let payload_len = 2; // (payload_len + 2) * 4 = 16
        let reserved = 0;
        let spi = 305419896;
        let sequence_number = 2271560481;
        let auth_data = [1, 2, 3, 4];

        // Write values.
        let mut writer = AuthenticationHeaderWriter::new(&mut bytes).unwrap();
        writer.set_next_header(next_header);
        writer.set_payload_len(payload_len);
        writer.set_reserved(reserved);
        writer.set_spi(spi);
        writer.set_sequence_number(sequence_number);
        writer.set_authentication_data(&auth_data).unwrap();

        // Read values.
        let reader = AuthenticationHeaderReader::new(&bytes).unwrap();

        assert_eq!(reader.next_header(), next_header);
        assert_eq!(reader.payload_len(), payload_len);
        assert_eq!(reader.reserved(), reserved);
        assert_eq!(reader.spi(), spi);
        assert_eq!(reader.sequence_number(), sequence_number);
        assert_eq!(reader.authentication_data().unwrap(), &auth_data);
    }
}
