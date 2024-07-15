use crate::misc::bytes_to_mac;
use core::{fmt, str::from_utf8};

/// The minimum length of an Ethernet frame header in bytes.
pub const ETHERNET_MIN_HEADER_LENGTH: usize = 14;

/// The minimum length of an Ethernet frame in bytes.
pub const ETHERNET_MIN_FRAME_LENGTH: usize = 64;

/// The length of a single VLAN tag in bytes.
pub const VLAN_TAG_LENGTH: usize = 4;

/// Indicates VLAN tagging.
pub const ETHERTYPE_VLAN: u16 = 0x8100;

/// Indicates double VLAN tagging (Q-in-Q).
pub const ETHERTYPE_QINQ: u16 = 0x88A8;

/// Writes Ethernet header fields.
pub struct EthernetWriter<'a> {
    pub bytes: &'a mut [u8],
    header_len: usize,
}

impl<'a> EthernetWriter<'a> {
    /// Creates a new `EthernetWriter` from the given slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ETHERNET_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Ethernet frame.");
        }

        Ok(Self {
            bytes,
            header_len: ETHERNET_MIN_HEADER_LENGTH,
        })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Sets the destination MAC address field.
    #[inline]
    pub fn set_dest_mac(&mut self, dest: &[u8; 6]) {
        self.bytes[0] = dest[0];
        self.bytes[1] = dest[1];
        self.bytes[2] = dest[2];
        self.bytes[3] = dest[3];
        self.bytes[4] = dest[4];
        self.bytes[5] = dest[5];
    }

    /// Sets the source MAC address field.
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
        let offset = self.header_len - ETHERNET_MIN_HEADER_LENGTH;
        self.bytes[12 + offset] = (ethertype >> 8) as u8;
        self.bytes[13 + offset] = (ethertype & 0xFF) as u8;
    }

    /// Sets a VLAN tag.
    ///
    /// Optionally present in the Ethernet frame header.
    ///
    /// Increases the header length by VLAN_TAG_LENGTH.
    #[inline]
    pub fn set_vlan_tag(&mut self, tpid: u16, tci: u16) -> Result<(), &'static str> {
        if self.bytes.len() < self.header_len + VLAN_TAG_LENGTH {
            return Err("Slice is too short to contain VLAN tagging.");
        }

        self.bytes[12] = (tpid >> 8) as u8;
        self.bytes[13] = (tpid & 0xFF) as u8;
        self.bytes[14] = (tci >> 8) as u8;
        self.bytes[15] = (tci & 0xFF) as u8;

        self.header_len += VLAN_TAG_LENGTH;

        Ok(())
    }

    /// Sets a double VLAN tag (Q-in-Q).
    ///
    /// Optionally present in the Ethernet frame header.
    ///
    /// Increases the header length by 2 * VLAN_TAG_LENGTH.
    #[inline]
    pub fn set_double_vlan_tag(
        &mut self,
        outer_tpid: u16,
        outer_tci: u16,
        inner_tpid: u16,
        inner_tci: u16,
    ) -> Result<(), &'static str> {
        if self.bytes.len() < self.header_len + 2 * VLAN_TAG_LENGTH {
            return Err("Slice is too short to contain double VLAN tagging.");
        }

        self.bytes[12] = (outer_tpid >> 8) as u8;
        self.bytes[13] = (outer_tpid & 0xFF) as u8;
        self.bytes[14] = (outer_tci >> 8) as u8;
        self.bytes[15] = (outer_tci & 0xFF) as u8;

        self.bytes[16] = (inner_tpid >> 8) as u8;
        self.bytes[17] = (inner_tpid & 0xFF) as u8;
        self.bytes[18] = (inner_tci >> 8) as u8;
        self.bytes[19] = (inner_tci & 0xFF) as u8;

        self.header_len += 2 * VLAN_TAG_LENGTH;

        Ok(())
    }
}

/// Reads Ethernet header fields.
#[derive(PartialEq)]
pub struct EthernetReader<'a> {
    pub bytes: &'a [u8],
    header_len: usize,
}

impl<'a> EthernetReader<'a> {
    /// Creates a new `EthernetReader` from the given slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ETHERNET_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an Ethernet frame.");
        }

        let header_len = Self::calculate_header_len(bytes)?;

        Ok(Self { bytes, header_len })
    }

    /// Calculates the header length of an Ethernet frame.
    ///
    /// Depending on the presence of VLAN tagging, the header length may vary.
    #[inline]
    pub fn calculate_header_len(bytes: &[u8]) -> Result<usize, &'static str> {
        let mut header_len = ETHERNET_MIN_HEADER_LENGTH;

        let ethertype = ((bytes[12] as u16) << 8) | (bytes[13] as u16);

        match ethertype {
            ETHERTYPE_VLAN => {
                if bytes.len() < ETHERNET_MIN_HEADER_LENGTH + VLAN_TAG_LENGTH {
                    return Err("Slice is too short to contain VLAN tagging.");
                }

                header_len += VLAN_TAG_LENGTH;
            }
            ETHERTYPE_QINQ => {
                if bytes.len() < ETHERNET_MIN_HEADER_LENGTH + 2 * VLAN_TAG_LENGTH {
                    return Err("Slice is too short to contain double VLAN tagging.");
                }

                let next_tpid = ((bytes[16] as u16) << 8) | (bytes[17] as u16);

                if next_tpid != ETHERTYPE_VLAN {
                    return Err("Invalid double VLAN tag.");
                }

                header_len += 2 * VLAN_TAG_LENGTH;
            }
            _ => {}
        }

        Ok(header_len)
    }

    /// Checks if the Ethernet frame is VLAN tagged.
    #[inline]
    pub fn is_vlan_tagged(bytes: &[u8]) -> bool {
        let ethertype = ((bytes[12] as u16) << 8) | (bytes[13] as u16);
        ethertype == ETHERTYPE_VLAN
    }

    /// Checks if the Ethernet frame is double VLAN tagged (Q-in-Q).
    #[inline]
    pub fn is_vlan_double_tagged(bytes: &[u8]) -> bool {
        let ethertype = ((bytes[12] as u16) << 8) | (bytes[13] as u16);
        ethertype == ETHERTYPE_QINQ
    }

    /// Returns the destination MAC address field.
    #[inline]
    pub fn dest_mac(&self) -> &[u8] {
        &self.bytes[0..6]
    }

    /// Returns the source MAC address field.
    #[inline]
    pub fn src_mac(&self) -> &[u8] {
        &self.bytes[6..12]
    }

    /// Returns the EtherType field field.
    ///
    /// Indicates which network protocol is encapsulated.
    #[inline]
    pub fn ethertype(&self) -> u16 {
        let offset = self.header_len - ETHERNET_MIN_HEADER_LENGTH;
        ((self.bytes[12 + offset] as u16) << 8) | (self.bytes[13 + offset] as u16)
    }

    /// Returns the VLAN tag.
    ///
    /// Optionally present in the Ethernet frame header.
    #[inline]
    pub fn vlan_tag(&self) -> Option<(u16, u16)> {
        if !Self::is_vlan_tagged(self.bytes) {
            return None;
        }

        let tpid = ((self.bytes[12] as u16) << 8) | (self.bytes[13] as u16);
        let tci = ((self.bytes[14] as u16) << 8) | (self.bytes[15] as u16);

        Some((tpid, tci))
    }

    /// Returns the double VLAN tag (Q-in-Q).
    ///
    /// Optionally present in the Ethernet frame header.
    #[inline]
    pub fn double_vlan_tag(&self) -> Option<((u16, u16), (u16, u16))> {
        if !Self::is_vlan_double_tagged(self.bytes) {
            return None;
        }

        let outer_tpid = ((self.bytes[12] as u16) << 8) | (self.bytes[13] as u16);
        let outer_tci = ((self.bytes[14] as u16) << 8) | (self.bytes[15] as u16);
        let inner_tpid = ((self.bytes[16] as u16) << 8) | (self.bytes[17] as u16);
        let inner_tci = ((self.bytes[18] as u16) << 8) | (self.bytes[19] as u16);

        Some(((outer_tpid, outer_tci), (inner_tpid, inner_tci)))
    }

    /// Returns the header length in bytes.
    #[inline]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..self.header_len]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_len..]
    }
}

impl fmt::Debug for EthernetReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d_buf = [0u8; 18];
        let d_len = bytes_to_mac(self.dest_mac(), &mut d_buf);
        let d_hex = from_utf8(&d_buf[..d_len]).unwrap();
        let mut s_buf = [0u8; 18];
        let s_len = bytes_to_mac(self.src_mac(), &mut s_buf);
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
