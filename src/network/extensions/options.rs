use core::fmt;

pub const OPTIONS_HEADER_MIN_LEN: usize = 8;

/// Writes an Options extension header fields.
/// 
/// May be Hop-by-Hop or Destination Options.
pub struct OptionsHeaderWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> OptionsHeaderWriter<'a> {
    /// Creates a new `OptionsHeaderWriter` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < OPTIONS_HEADER_MIN_LEN {
            return Err("Slice is too short to contain an Options extension header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the total Wheader length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[1] as usize + 1) * 8
    }

    /// Sets the next header field.
    /// 
    /// Specifies the type of the next header.
    #[inline]
    pub fn set_next_header(&mut self, next_header: u8) {
        self.bytes[0] = next_header;
    }

    /// Sets the header extension length field.
    /// 
    /// Length of the header in 8 bytes, not including the first 8 bytes.
    #[inline]
    pub fn set_header_ext_len(&mut self, header_ext_len: u8) {
        self.bytes[1] = header_ext_len;
    }

    /// Sets the options and padding fields.
    /// 
    /// Is of variable length. Padding is added to ensure the header length is a multiple of 8 bytes.
    #[inline]
    pub fn set_options(&mut self, options: &[u8]) -> Result<(), &'static str> {
        if options.len() < 6 {
            return Err("Options field must be at least 6 bytes long.");
        }

        let start_offset = 2;
        let end_offset = start_offset + options.len();

        if end_offset > self.bytes.len() {
            return Err("Options exceed the allocated header length.");
        }

        let padding_len = (8 - (end_offset % 8)) % 8;
        let padding_offset = end_offset + padding_len;

        if padding_offset > self.bytes.len() {
            return Err("Padding exceeds the allocated header length.");
        }

        let extension_len = self.bytes[1] as usize * 8 + 6;

        if extension_len != options.len() + padding_len {
            return Err("Options length must match the header extension length.");
        }

        self.bytes[start_offset..end_offset].copy_from_slice(options);

        for i in end_offset..padding_offset {
            self.bytes[i] = 0;
        }

        Ok(())
    }
}

pub struct OptionsHeaderReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> OptionsHeaderReader<'a> {
    /// Creates a new `OptionsHeaderReader` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < OPTIONS_HEADER_MIN_LEN {
            return Err("Slice is too short to contain an Options extension header.");
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

    /// Returns the header extension length field.
    /// 
    /// Length of the header in 8 bytes, not including the first 8 bytes.
    #[inline]
    pub fn header_ext_len(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the options and padding fields.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        let start = 2;
        let end = self.header_len();
        &self.bytes[start..end]
    }

    /// Returns the total header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[1] as usize + 1) * 8
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len()..]
    }
}

impl fmt::Debug for OptionsHeaderReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OptionsHeaderReader")
            .field("next_header", &self.next_header())
            .field("header_ext_len", &self.header_ext_len())
            .field("options", &self.options())
            .finish()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0; 16];

        // Random values.
        let next_header = 6;
        let header_ext_len = 1;
        let options = [0; 7];

        // Write the Options extension header.
        let mut writer = OptionsHeaderWriter::new(&mut bytes).unwrap();
        writer.set_next_header(next_header);
        writer.set_header_ext_len(header_ext_len);
        writer.set_options(&options).unwrap();

        // Read the Options extension header.
        let reader = OptionsHeaderReader::new(&bytes).unwrap();
        assert_eq!(reader.next_header(), next_header);
        assert_eq!(reader.header_ext_len(), header_ext_len);
    }
}