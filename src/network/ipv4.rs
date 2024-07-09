use super::checksum::internet_checksum;
use crate::misc::IpFormatter;
use core::fmt;

/// The length of an IPv4 header in bytes without options.
pub const IPV4_MIN_HEADER_LENGTH: usize = 20;

/// Represents an IPv4 packet.
pub struct IPv4Builder<'a> {
    pub data: &'a mut [u8],
}

impl<'a> IPv4Builder<'a> {
    /// Creates a new `IPv4Packet` from the given data slice.
    /// Returns an error if the data Slice is too short to contain an IPv4 header.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < IPV4_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an IPv4 header.");
        }

        Ok(Self { data })
    }

    /// Returns the actual header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        (self.data[0] & 0x0f) as usize * 4
    }

    /// Sets the version field.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.data[0] = (self.data[0] & 0x0F) | (version << 4);
    }

    /// Sets the IHL field.
    #[inline]
    pub fn set_ihl(&mut self, ihl: u8) {
        self.data[0] = (self.data[0] & 0xF0) | (ihl & 0x0F);
    }

    /// Sets the DSCP field.
    #[inline]
    pub fn set_dscp(&mut self, dscp: u8) {
        self.data[1] = (self.data[1] & 0x03) | (dscp << 2);
    }

    /// Sets the ECN field.
    #[inline]
    pub fn set_ecn(&mut self, ecn: u8) {
        self.data[1] = (self.data[1] & 0xFC) | (ecn & 0x03);
    }

    /// Sets the total length field.
    #[inline]
    pub fn set_total_length(&mut self, total_length: u16) {
        self.data[2] = (total_length >> 8) as u8;
        self.data[3] = (total_length & 0xFF) as u8;
    }

    /// Sets the identification field.
    #[inline]
    pub fn set_identification(&mut self, identification: u16) {
        self.data[4] = (identification >> 8) as u8;
        self.data[5] = (identification & 0xFF) as u8;
    }

    /// Sets the flags field.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.data[6] = (self.data[6] & 0x1F) | ((flags << 5) & 0xE0);
    }

    /// Sets the fragment offset field.
    #[inline]
    pub fn set_fragment_offset(&mut self, fragment_offset: u16) {
        self.data[6] = (self.data[6] & 0xE0) | ((fragment_offset >> 8) & 0x1F) as u8;
        self.data[7] = (fragment_offset & 0xFF) as u8;
    }

    /// Sets the TTL field.
    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        self.data[8] = ttl;
    }

    /// Sets the protocol field.
    #[inline]
    pub fn set_protocol(&mut self, protocol: u8) {
        self.data[9] = protocol;
    }

    /// Sets the source IP address field.
    #[inline]
    pub fn set_src_ip(&mut self, src_ip: &[u8; 4]) {
        self.data[12] = src_ip[0];
        self.data[13] = src_ip[1];
        self.data[14] = src_ip[2];
        self.data[15] = src_ip[3];
    }

    /// Sets the destination IP address field.
    #[inline]
    pub fn set_dest_ip(&mut self, dest_ip: &[u8; 4]) {
        self.data[16] = dest_ip[0];
        self.data[17] = dest_ip[1];
        self.data[18] = dest_ip[2];
        self.data[19] = dest_ip[3];
    }

    /// Calculates the checksum field.
    ///
    /// Only includes the header.
    #[inline]
    pub fn set_checksum(&mut self) {
        self.data[10] = 0;
        self.data[11] = 0;
        let header_len = self.header_length();
        let checksum = internet_checksum(&self.data[..header_len], 0);
        self.data[10] = (checksum >> 8) as u8;
        self.data[11] = (checksum & 0xff) as u8;
    }
}

#[derive(PartialEq)]
pub struct IPv4Parser<'a> {
    pub data: &'a [u8],
}

impl<'a> IPv4Parser<'a> {
    /// Creates a new `IPv4Packet` from the given data slice.
    #[inline]
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < IPV4_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain an IPv4 header.");
        }

        Ok(Self { data })
    }

    /// Returns the actual header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        self.get_ihl() as usize * 4
    }

    /// Returns the version field.
    #[inline]
    pub fn get_version(&self) -> u8 {
        self.data[0] >> 4
    }

    /// Returns the IHL field.
    #[inline]
    pub fn get_ihl(&self) -> u8 {
        self.data[0] & 0x0f
    }

    /// Returns the DSCP field.
    #[inline]
    pub fn get_dscp(&self) -> u8 {
        self.data[1] >> 2
    }

    /// Returns the ECN field.
    #[inline]
    pub fn get_ecn(&self) -> u8 {
        self.data[1] & 0x03
    }

    /// Returns the total length field.
    #[inline]
    pub fn get_total_length(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }

    /// Returns the identification field.
    #[inline]
    pub fn get_identification(&self) -> u16 {
        ((self.data[4] as u16) << 8) | (self.data[5] as u16)
    }

    /// Returns the flags field.
    #[inline]
    pub fn get_flags(&self) -> u8 {
        self.data[6] >> 5
    }

    /// Returns the fragment offset field.
    #[inline]
    pub fn get_fragment_offset(&self) -> u16 {
        ((self.data[6] as u16 & 0x1F) << 8) | (self.data[7] as u16)
    }

    /// Returns the TTL field.
    #[inline]
    pub fn get_ttl(&self) -> u8 {
        self.data[8]
    }

    /// Returns the protocol field.
    #[inline]
    pub fn get_protocol(&self) -> u8 {
        self.data[9]
    }

    /// Returns a reference to the source IP address field.
    #[inline]
    pub fn get_src_ip(&self) -> &[u8] {
        &self.data[12..16]
    }

    /// Returns a reference to the destination IP address field.
    #[inline]
    pub fn get_dest_ip(&self) -> &[u8] {
        &self.data[16..20]
    }

    /// Returns the checksum field.
    #[inline]
    pub fn get_checksum(&self) -> u16 {
        ((self.data[10] as u16) << 8) | (self.data[11] as u16)
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn get_header(&self) -> &'a [u8] {
        &self.data[..self.header_length()]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn get_payload(&self) -> &'a [u8] {
        &self.data[self.header_length()..]
    }
}

impl<'a> fmt::Debug for IPv4Parser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let src_ip = self.get_src_ip();
        let dest_ip = self.get_dest_ip();
        f.debug_struct("IPv4Packet")
            .field("version", &self.get_version())
            .field("ihl", &self.get_ihl())
            .field("dscp", &self.get_dscp())
            .field("ecn", &self.get_ecn())
            .field("total_length", &self.get_total_length())
            .field("identification", &self.get_identification())
            .field("flags", &self.get_flags())
            .field("fragment_offset", &self.get_fragment_offset())
            .field("ttl", &self.get_ttl())
            .field("protocol", &self.get_protocol())
            .field("checksum", &self.get_checksum())
            .field("src_ip", &IpFormatter(&src_ip))
            .field("dest_ip", &IpFormatter(&dest_ip))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet data.
        let mut data = [0u8; 20];

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

        // Create a new IPv4 packet from the raw data.
        let mut builder = IPv4Builder::new(&mut data).unwrap();

        // Set the fields.
        builder.set_version(version);
        builder.set_ihl(ihl);
        builder.set_dscp(dscp);
        builder.set_ecn(ecn);
        builder.set_total_length(total_length);
        builder.set_identification(identification);
        builder.set_flags(flags);
        builder.set_fragment_offset(fragment_offset);
        builder.set_ttl(ttl);
        builder.set_protocol(protocol);
        builder.set_src_ip(&src_ip);
        builder.set_dest_ip(&dest_ip);
        builder.set_checksum();

        let parser = IPv4Parser::new(&data).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(parser.get_version(), version);
        assert_eq!(parser.get_ihl(), ihl);
        assert_eq!(parser.get_dscp(), dscp);
        assert_eq!(parser.get_ecn(), ecn);
        assert_eq!(parser.get_total_length(), total_length);
        assert_eq!(parser.get_identification(), identification);
        assert_eq!(parser.get_flags(), flags);
        assert_eq!(parser.get_fragment_offset(), fragment_offset);
        assert_eq!(parser.get_ttl(), ttl);
        assert_eq!(parser.get_protocol(), protocol);
        assert_eq!(parser.get_src_ip(), src_ip);
        assert_eq!(parser.get_dest_ip(), dest_ip);
    }
}
