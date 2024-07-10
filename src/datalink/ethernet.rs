use crate::misc::to_hex_string;
use core::{fmt, str::from_utf8};

/// The minimum length of an Ethernet frame header in bytes.
pub const ETHERNET_MIN_HEADER_LENGTH: usize = 14;

/// The minimum length of an Ethernet frame in bytes.
pub const ETHERNET_MIN_FRAME_LENGTH: usize = 64;

/// Writes Ethernet header fields.
pub struct EthernetWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> EthernetWriter<'a> {
    /// Creates a new `EthernetFrame` from the given slice.
    ///
    /// Returns an error if the smallest possible Ethernet header does not fit in the slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ETHERNET_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Ethernet frame.");
        }

        Ok(Self { bytes })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ETHERNET_MIN_HEADER_LENGTH
    }

    /// Sets the destination MAC address.
    #[inline]
    pub fn set_dest_mac(&mut self, dest: &[u8; 6]) {
        self.bytes[0] = dest[0];
        self.bytes[1] = dest[1];
        self.bytes[2] = dest[2];
        self.bytes[3] = dest[3];
        self.bytes[4] = dest[4];
        self.bytes[5] = dest[5];
    }

    /// Sets the source MAC address.
    #[inline]
    pub fn set_src_mac(&mut self, src: &[u8; 6]) {
        self.bytes[6] = src[0];
        self.bytes[7] = src[1];
        self.bytes[8] = src[2];
        self.bytes[9] = src[3];
        self.bytes[10] = src[4];
        self.bytes[11] = src[5];
    }

    /// Sets the EtherType field.
    ///
    /// EtherType indicates which protocol is encapsulated in the payload.
    #[inline]
    pub fn set_ethertype(&mut self, ethertype: u16) {
        self.bytes[12] = (ethertype >> 8) as u8;
        self.bytes[13] = (ethertype & 0xFF) as u8;
    }
}

/// Reads Ethernet header fields.
#[derive(PartialEq)]
pub struct EthernetReader<'a> {
    bytes: &'a [u8],
}

impl<'a> EthernetReader<'a> {
    /// Creates a new `EthernetParser` from the given slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ETHERNET_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Ethernet frame.");
        }

        Ok(Self { bytes })
    }

    /// Returns a reference to the destination MAC address.
    #[inline]
    pub fn dest_mac(&self) -> &[u8] {
        &self.bytes[0..6]
    }

    /// Returns a reference to the source MAC address.
    #[inline]
    pub fn src_mac(&self) -> &[u8] {
        &self.bytes[6..12]
    }

    /// Returns a reference to the EtherType field.
    ///
    /// EtherType indicates which protocol is encapsulated in the payload.
    #[inline]
    pub fn ethertype(&self) -> u16 {
        ((self.bytes[12] as u16) << 8) | (self.bytes[13] as u16)
    }

    /// Returns the header length in bytes.
    #[inline]
    pub const fn header_len(&self) -> usize {
        ETHERNET_MIN_HEADER_LENGTH
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..ETHERNET_MIN_HEADER_LENGTH]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[ETHERNET_MIN_HEADER_LENGTH..]
    }
}

impl<'a> fmt::Debug for EthernetReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d_buf = [0u8; 18];
        let d_len = to_hex_string(self.dest_mac(), &mut d_buf);
        let d_hex = from_utf8(&d_buf[..d_len]).unwrap();
        let mut s_buf = [0u8; 18];
        let s_len = to_hex_string(self.src_mac(), &mut s_buf);
        let s_hex = from_utf8(&s_buf[..s_len]).unwrap();
        f.debug_struct("EthernetFrame")
            .field("dest_mac", &d_hex)
            .field("src_mac", &s_hex)
            .field("ethertype", &self.ethertype())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 14];

        // Random values.
        let src = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let dest = [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
        let ethertype = 2048;

        // Create an Ethernet frame writer.
        let mut writer = EthernetWriter::new(&mut bytes).unwrap();

        // Set the fields.
        writer.set_src_mac(&src);
        writer.set_dest_mac(&dest);
        writer.set_ethertype(ethertype);

        // Create an Ethernet frame reader.
        let reader = EthernetReader::new(&bytes).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(reader.src_mac(), src);
        assert_eq!(reader.dest_mac(), dest);
        assert_eq!(reader.ethertype(), ethertype);
    }
}
