use core::fmt;

/// The minimum length of a Routing extension header.
pub const ROUTING_HEADER_MIN_LEN: usize = 8;

/// Writes the Routing extension header fields.
pub struct RoutingHeaderWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> RoutingHeaderWriter<'a> {
    /// Creates a new `RoutingHeaderWriter` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ROUTING_HEADER_MIN_LEN {
            return Err("Slice is too short to contain a Routing extension header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the total header length in bytes.
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
    /// 
    /// E.g. Header length = (header_ext_len + 1) * 8.
    #[inline]
    pub fn set_header_ext_len(&mut self, header_ext_len: u8) {
        self.bytes[1] = header_ext_len;
    }

    /// Sets the routing type field.
    ///
    /// Value between 0 and 255, see IANA:
    /// - 0: deprecated, since it enabled DoS attacks.
    /// - 1: deprecated, used for the Nimrod project by DARPA.
    /// - 2: allowed, limited version of type 0, used for Mobile IPv6.
    /// - 3: allowed, RPL Source Route Header for low-power and lossy networks.
    /// - 4: allowed, Segment Routing Header (SHR).
    #[inline]
    pub fn set_routing_type(&mut self, routing_type: u8) {
        self.bytes[2] = routing_type;
    }

    /// Sets the segments left field.
    ///
    /// Number of nodes this packet has to visit before reaching its final destination.
    #[inline]
    pub fn set_segments_left(&mut self, segments_left: u8) {
        self.bytes[3] = segments_left;
    }

    /// Sets the data field.
    ///
    /// The data field is a variable-length field.
    ///
    /// The first 4 bytes are reserved with zeroes.
    ///
    /// If you set data then set blocks of 8 bytes.
    #[inline]
    pub fn set_data(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() < 4 {
            return Err("Type-specific data must be at least 4 bytes long.");
        }

        let extension_len = self.bytes[1] as usize * 8;

        if extension_len != data.len() {
            return Err("Type-specific data length must match the header extension length.");
        }

        let start_offset = 8;
        let end_offset = start_offset + data.len();

        if end_offset > self.bytes.len() {
            return Err("Type-specific data exceeds the allocated header length.");
        }

        self.bytes[start_offset..end_offset].copy_from_slice(data);

        Ok(())
    }
}

/// Reads the Routing extension header fields.
pub struct RoutingHeaderReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> RoutingHeaderReader<'a> {
    /// Creates a new `RoutingHeaderReader` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ROUTING_HEADER_MIN_LEN {
            return Err("Slice is too short to contain a Routing extension header.");
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
    /// 
    /// E.g. Header length = (header_ext_len + 1) * 8.
    #[inline]
    pub fn header_ext_len(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the routing type field.
    ///
    /// Value between 0 and 255, see IANA:
    /// - 0: deprecated, since it enabled DoS attacks.
    /// - 1: deprecated, used for the Nimrod project by DARPA.
    /// - 2: allowed, limited version of type 0, used for Mobile IPv6.
    /// - 3: allowed, RPL Source Route Header for low-power and lossy networks.
    /// - 4: allowed, Segment Routing Header (SHR).
    #[inline]
    pub fn routing_type(&self) -> u8 {
        self.bytes[2]
    }

    /// Returns the segments left field.
    ///
    /// Number of nodes this packet has to visit before reaching its final destination.
    #[inline]
    pub fn segments_left(&self) -> u8 {
        self.bytes[3]
    }

    /// Returns the data field.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let start = 4;
        let end = self.header_len();
        &self.bytes[start..end]
    }

    /// Returns the total header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[1] as usize + 1) * 8
    }

    /// Returns a reference to the header.
    /// 
    /// May fail if the indicated header length exceeds the allocated buffer.
    #[inline]
    pub fn header(&self) -> Result<&'a [u8], &'static str> {
        let end = self.header_len();

        if end > self.bytes.len() {
            return Err("Indicated IPv6 routing header length exceeds the allocated buffer.");
        }

        Ok(&self.bytes[..end])
    }

    /// Returns a reference to the payload.
    /// 
    /// May fail if the indicated header length exceeds the allocated buffer.
    #[inline]
    pub fn payload(&self) -> Result<&'a [u8], &'static str> {
        let start = self.header_len();

        if start > self.bytes.len() {
            return Err("Indicated IPv6 routing header length exceeds the allocated buffer.");
        }

        Ok(&self.bytes[self.header_len()..])
    }
}

impl fmt::Debug for RoutingHeaderReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingExtensionHeader")
            .field("next_header", &self.next_header())
            .field("header_ext_len", &self.header_ext_len())
            .field("routing_type", &self.routing_type())
            .field("segments_left", &self.segments_left())
            .field("data", &self.data())
            .finish()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 16];

        // Random values.
        let next_header = 6;
        let header_ext_len = 1; // (header_ext_len + 1) * 8 = 16
        let routing_type = 2;
        let segments_left = 3;
        let data = [4, 5, 6, 7, 8, 9, 10, 11];

        // Write the Routing extension header.
        let mut writer = RoutingHeaderWriter::new(&mut bytes).unwrap();
        writer.set_next_header(next_header);
        writer.set_header_ext_len(header_ext_len);
        writer.set_routing_type(routing_type);
        writer.set_segments_left(segments_left);
        writer.set_data(&data).unwrap();

        // Read the Routing extension header.
        let reader = RoutingHeaderReader::new(&bytes).unwrap();
        assert_eq!(reader.next_header(), next_header);
        assert_eq!(reader.header_ext_len(), header_ext_len);
        assert_eq!(reader.routing_type(), routing_type);
        assert_eq!(reader.segments_left(), segments_left);
        assert_eq!(reader.data(), [0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 10, 11]);
    }
}
