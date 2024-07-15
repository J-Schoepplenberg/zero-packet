use super::checksum::internet_checksum;
use crate::misc::IpFormatter;
use core::fmt;

/// The length of an IPv4 header in bytes without options.
pub const IPV4_MIN_HEADER_LENGTH: usize = 20;

/// Writes IPv4 header fields.
pub struct IPv4Writer<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> IPv4Writer<'a> {
    /// Creates a new `IPv4Writer` from the given slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < IPV4_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an IPv4 header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the actual header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[0] & 0x0f) as usize * 4
    }

    /// Sets the version field.
    ///
    /// Indicates the IP version number. Should be set to 4.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.bytes[0] = (self.bytes[0] & 0x0F) | (version << 4);
    }

    /// Sets the IHL field.
    #[inline]
    pub fn set_ihl(&mut self, ihl: u8) {
        self.bytes[0] = (self.bytes[0] & 0xF0) | (ihl & 0x0F);
    }

    /// Sets the DSCP field.
    #[inline]
    pub fn set_dscp(&mut self, dscp: u8) {
        self.bytes[1] = (self.bytes[1] & 0x03) | (dscp << 2);
    }

    /// Sets the ECN field.
    #[inline]
    pub fn set_ecn(&mut self, ecn: u8) {
        self.bytes[1] = (self.bytes[1] & 0xFC) | (ecn & 0x03);
    }

    /// Sets the total length field.
    ///
    /// Should include the entire packet (header and payload).
    #[inline]
    pub fn set_total_length(&mut self, total_length: u16) {
        self.bytes[2] = (total_length >> 8) as u8;
        self.bytes[3] = (total_length & 0xFF) as u8;
    }

    /// Sets the identification field.
    #[inline]
    pub fn set_id(&mut self, identification: u16) {
        self.bytes[4] = (identification >> 8) as u8;
        self.bytes[5] = (identification & 0xFF) as u8;
    }

    /// Sets the flags field.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.bytes[6] = (self.bytes[6] & 0x1F) | ((flags << 5) & 0xE0);
    }

    /// Sets the fragment offset field.
    #[inline]
    pub fn set_fragment_offset(&mut self, fragment_offset: u16) {
        self.bytes[6] = (self.bytes[6] & 0xE0) | ((fragment_offset >> 8) & 0x1F) as u8;
        self.bytes[7] = (fragment_offset & 0xFF) as u8;
    }

    /// Sets the TTL field.
    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        self.bytes[8] = ttl;
    }

    /// Sets the protocol field.
    #[inline]
    pub fn set_protocol(&mut self, protocol: u8) {
        self.bytes[9] = protocol;
    }

    /// Sets the source IP address field.
    #[inline]
    pub fn set_src_ip(&mut self, src_ip: &[u8; 4]) {
        self.bytes[12] = src_ip[0];
        self.bytes[13] = src_ip[1];
        self.bytes[14] = src_ip[2];
        self.bytes[15] = src_ip[3];
    }

    /// Sets the destination IP address field.
    #[inline]
    pub fn set_dest_ip(&mut self, dest_ip: &[u8; 4]) {
        self.bytes[16] = dest_ip[0];
        self.bytes[17] = dest_ip[1];
        self.bytes[18] = dest_ip[2];
        self.bytes[19] = dest_ip[3];
    }

    /// Calculates the checksum field.
    ///
    /// Only includes the header.
    #[inline]
    pub fn set_checksum(&mut self) {
        self.bytes[10] = 0;
        self.bytes[11] = 0;
        let header_len = self.header_len();
        let checksum = internet_checksum(&self.bytes[..header_len], 0);
        self.bytes[10] = (checksum >> 8) as u8;
        self.bytes[11] = (checksum & 0xff) as u8;
    }
}

/// Reads IPv4 header fields.
#[derive(PartialEq)]
pub struct IPv4Reader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> IPv4Reader<'a> {
    /// Creates a new `IPv4Reader` from the given slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < IPV4_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an IPv4 header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.bytes[0] >> 4
    }

    /// Returns the IHL field.
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.bytes[0] & 0x0f
    }

    /// Returns the DSCP field.
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.bytes[1] >> 2
    }

    /// Returns the ECN field.
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.bytes[1] & 0x03
    }

    /// Returns the total length field.
    ///
    /// Includes the entire packet (header and payload).
    #[inline]
    pub fn total_length(&self) -> u16 {
        ((self.bytes[2] as u16) << 8) | (self.bytes[3] as u16)
    }

    /// Returns the identification field.
    #[inline]
    pub fn id(&self) -> u16 {
        ((self.bytes[4] as u16) << 8) | (self.bytes[5] as u16)
    }

    /// Returns the flags field.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.bytes[6] >> 5
    }

    /// Returns the fragment offset field.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        ((self.bytes[6] as u16 & 0x1F) << 8) | (self.bytes[7] as u16)
    }

    /// Returns the TTL field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }

    /// Returns the protocol field.
    #[inline]
    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    /// Returns a reference to the source IP address field.
    #[inline]
    pub fn src_ip(&self) -> &[u8] {
        &self.bytes[12..16]
    }

    /// Returns a reference to the destination IP address field.
    #[inline]
    pub fn dest_ip(&self) -> &[u8] {
        &self.bytes[16..20]
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        ((self.bytes[10] as u16) << 8) | (self.bytes[11] as u16)
    }

    /// Returns the actual header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.ihl() as usize * 4
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..self.header_len()]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len()..]
    }

    /// Verifies the checksum field.
    #[inline]
    pub fn valid_checksum(&self) -> bool {
        internet_checksum(self.header(), 0) == 0
    }
}

impl fmt::Debug for IPv4Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let src_ip = self.src_ip();
        let dest_ip = self.dest_ip();
        f.debug_struct("IPv4Packet")
            .field("version", &self.version())
            .field("ihl", &self.ihl())
            .field("dscp", &self.dscp())
            .field("ecn", &self.ecn())
            .field("total_length", &self.total_length())
            .field("identification", &self.id())
            .field("flags", &self.flags())
            .field("fragment_offset", &self.fragment_offset())
            .field("ttl", &self.ttl())
            .field("protocol", &self.protocol())
            .field("checksum", &self.checksum())
            .field("src_ip", &IpFormatter(src_ip))
            .field("dest_ip", &IpFormatter(dest_ip))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 20];

        // Random values.
        let version = 4;
        let ihl = 5;
        let src_ip = [192, 168, 1, 1];
        let dest_ip = [192, 168, 1, 2];
        let dscp = 0;
        let ecn = 0;
        let total_length = 40;
        let identification = 0;
        let flags = 2;
        let fragment_offset = 0;
        let ttl = 64;
        let protocol = 0x06;

        // Create a IPv4 packet writer.
        let mut writer = IPv4Writer::new(&mut bytes).unwrap();

        // Set the fields.
        writer.set_version(version);
        writer.set_ihl(ihl);
        writer.set_dscp(dscp);
        writer.set_ecn(ecn);
        writer.set_total_length(total_length);
        writer.set_id(identification);
        writer.set_flags(flags);
        writer.set_fragment_offset(fragment_offset);
        writer.set_ttl(ttl);
        writer.set_protocol(protocol);
        writer.set_src_ip(&src_ip);
        writer.set_dest_ip(&dest_ip);
        writer.set_checksum();

        // Create a IPv4 packet reader.
        let reader = IPv4Reader::new(&bytes).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(reader.version(), version);
        assert_eq!(reader.ihl(), ihl);
        assert_eq!(reader.dscp(), dscp);
        assert_eq!(reader.ecn(), ecn);
        assert_eq!(reader.total_length(), total_length);
        assert_eq!(reader.id(), identification);
        assert_eq!(reader.flags(), flags);
        assert_eq!(reader.fragment_offset(), fragment_offset);
        assert_eq!(reader.ttl(), ttl);
        assert_eq!(reader.protocol(), protocol);
        assert_eq!(reader.src_ip(), src_ip);
        assert_eq!(reader.dest_ip(), dest_ip);
    }
}
