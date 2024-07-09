use crate::misc::to_hex_string;
use core::{fmt, str::from_utf8};

/// The minimum length of an Ethernet frame header in bytes.
pub const ETHERNET_MIN_HEADER_LENGTH: usize = 14;

/// The minimum length of an Ethernet frame in bytes.
pub const ETHERNET_MIN_FRAME_LENGTH: usize = 64;

/// Represents an Ethernet frame builder.
pub struct EthernetBuilder<'a> {
    pub data: &'a mut [u8],
}

impl<'a> EthernetBuilder<'a> {
    /// Creates a new `EthernetFrame` from the given slice.
    ///
    /// Returns an error if the smallest possible Ethernet header does not fit in the slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < ETHERNET_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Ethernet frame.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        ETHERNET_MIN_HEADER_LENGTH
    }

    /// Sets the destination MAC address.
    #[inline]
    pub fn set_dest_mac(&mut self, dest: &[u8; 6]) {
        self.data[0] = dest[0];
        self.data[1] = dest[1];
        self.data[2] = dest[2];
        self.data[3] = dest[3];
        self.data[4] = dest[4];
        self.data[5] = dest[5];
    }

    /// Sets the source MAC address.
    #[inline]
    pub fn set_src_mac(&mut self, src: &[u8; 6]) {
        self.data[6] = src[0];
        self.data[7] = src[1];
        self.data[8] = src[2];
        self.data[9] = src[3];
        self.data[10] = src[4];
        self.data[11] = src[5];
    }

    /// Sets the EtherType field.
    ///
    /// EtherType indicates which protcol is encapsulated in the payload.
    #[inline]
    pub fn set_ethertype(&mut self, ethertype: u16) {
        self.data[12] = (ethertype >> 8) as u8;
        self.data[13] = (ethertype & 0xFF) as u8;
    }
}

/// Represents an Ethernet frame parser.
#[derive(PartialEq)]
pub struct EthernetParser<'a> {
    data: &'a [u8],
}

impl<'a> EthernetParser<'a> {
    /// Creates a new `EthernetParser` from the given slice.
    #[inline]
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < ETHERNET_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Ethernet frame.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        ETHERNET_MIN_HEADER_LENGTH
    }

    /// Returns a reference to the destination MAC address.
    #[inline]
    pub fn get_dest_mac(&self) -> &[u8] {
        &self.data[0..6]
    }

    /// Returns a reference to the source MAC address..
    #[inline]
    pub fn get_src_mac(&self) -> &[u8] {
        &self.data[6..12]
    }

    /// Returns a reference to the EtherType field.
    ///
    /// EtherType indicates which protcol is encapsulated in the payload.
    #[inline]
    pub fn get_ethertype(&self) -> u16 {
        ((self.data[12] as u16) << 8) | (self.data[13] as u16)
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[ETHERNET_MIN_HEADER_LENGTH..]
    }
}

impl<'a> fmt::Debug for EthernetParser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d_buf = [0u8; 18];
        let d_len = to_hex_string(self.get_dest_mac(), &mut d_buf);
        let d_hex = from_utf8(&d_buf[..d_len]).unwrap();
        let mut s_buf = [0u8; 18];
        let s_len = to_hex_string(self.get_src_mac(), &mut s_buf);
        let s_hex = from_utf8(&s_buf[..s_len]).unwrap();
        f.debug_struct("EthernetFrame")
            .field("dest_mac", &d_hex)
            .field("src_mac", &s_hex)
            .field("ethertype", &self.get_ethertype())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet data.
        let mut data = [0u8; 14];

        // Random values.
        let src = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let dest = [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
        let ethertype = 2048;

        // Create an Ethernet frame builder from the raw data.
        let mut builder = EthernetBuilder::new(&mut data).unwrap();

        // Set the fields.
        builder.set_src_mac(&src);
        builder.set_dest_mac(&dest);
        builder.set_ethertype(ethertype);

        // Create an Ethernet frame parser from the raw data.
        let parser = EthernetParser::new(&data).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(parser.get_src_mac(), src);
        assert_eq!(parser.get_dest_mac(), dest);
        assert_eq!(parser.get_ethertype(), ethertype);
    }
}
