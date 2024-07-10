use crate::network::checksum::{internet_checksum, pseudo_header};
use core::fmt;

/// The minimum length of a TCP header in bytes.
pub const TCP_MIN_HEADER_LENGTH: usize = 20;

/// Represents a TCP segment.
pub struct TcpWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> TcpWriter<'a> {
    /// Creates a new `TcpSegment` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < TCP_MIN_HEADER_LENGTH {
            return Err("Slice is too short to contain a TCP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.bytes[12] >> 4) as usize * 4
    }

    /// Sets the source port field.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.bytes[0] = (src_port >> 8) as u8;
        self.bytes[1] = (src_port & 0xFF) as u8;
    }

    /// Sets the destination port field.
    #[inline]
    pub fn set_dest_port(&mut self, dest_port: u16) {
        self.bytes[2] = (dest_port >> 8) as u8;
        self.bytes[3] = (dest_port & 0xFF) as u8;
    }

    /// Sets the sequence number field.
    #[inline]
    pub fn set_sequence_number(&mut self, sequence_number: u32) {
        self.bytes[4] = (sequence_number >> 24) as u8;
        self.bytes[5] = (sequence_number >> 16) as u8;
        self.bytes[6] = (sequence_number >> 8) as u8;
        self.bytes[7] = (sequence_number & 0xFF) as u8;
    }

    /// Sets the acknowledgment number field.
    #[inline]
    pub fn set_ack_number(&mut self, acknowledgment_number: u32) {
        self.bytes[8] = (acknowledgment_number >> 24) as u8;
        self.bytes[9] = (acknowledgment_number >> 16) as u8;
        self.bytes[10] = (acknowledgment_number >> 8) as u8;
        self.bytes[11] = (acknowledgment_number & 0xFF) as u8;
    }

    /// Sets the data offset field.
    #[inline]
    pub fn set_data_offset(&mut self, data_offset: u8) {
        self.bytes[12] = (data_offset << 4) | (self.bytes[12] & 0x0f);
    }

    /// Sets the reserved field.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        self.bytes[12] = (self.bytes[12] & 0xf0) | (reserved & 0x0f);
    }

    /// Sets the flags field.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.bytes[13] = flags;
    }

    /// Sets the window size field.
    #[inline]
    pub fn set_window_size(&mut self, window_size: u16) {
        self.bytes[14] = (window_size >> 8) as u8;
        self.bytes[15] = (window_size & 0xFF) as u8;
    }

    /// Sets the urgent pointer field.
    #[inline]
    pub fn set_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.bytes[18] = (urgent_pointer >> 8) as u8;
        self.bytes[19] = (urgent_pointer & 0xFF) as u8;
    }

    /// Calculates the checksum field for error checking.
    ///
    /// Consists of the IP pseudo-header, TCP header and payload.
    #[inline]
    pub fn set_checksum(&mut self, src_ip: &[u8; 4], dest_ip: &[u8; 4]) {
        self.bytes[16] = 0;
        self.bytes[17] = 0;
        let pseudo_header = pseudo_header(src_ip, dest_ip, 6, self.bytes.len());
        let checksum = internet_checksum(self.bytes, pseudo_header);
        self.bytes[16] = (checksum >> 8) as u8;
        self.bytes[17] = (checksum & 0xff) as u8;
    }
}


#[derive(PartialEq)]
pub struct TcpReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> TcpReader<'a> {
    /// Creates a new `TcpSegment` from the given data slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < TCP_MIN_HEADER_LENGTH{
            return Err("Slice is too short to contain a TCP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the source port field.
    #[inline]
    pub fn src_port(&self) -> u16 {
        ((self.bytes[0] as u16) << 8) | (self.bytes[1] as u16)
    }

    /// Returns the destination port field.
    #[inline]
    pub fn dest_port(&self) -> u16 {
        ((self.bytes[2] as u16) << 8) | (self.bytes[3] as u16)
    }

    /// Returns the sequence number field.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        ((self.bytes[4] as u32) << 24)
            | ((self.bytes[5] as u32) << 16)
            | ((self.bytes[6] as u32) << 8)
            | (self.bytes[7] as u32)
    }

    /// Returns the acknowledgment number field.
    #[inline]
    pub fn ack_number(&self) -> u32 {
        ((self.bytes[8] as u32) << 24)
            | ((self.bytes[9] as u32) << 16)
            | ((self.bytes[10] as u32) << 8)
            | (self.bytes[11] as u32)
    }

    /// Returns the data offset field.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.bytes[12] >> 4
    }

    /// Returns the reserved field.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.bytes[12] & 0x0F
    }

    /// Returns the flags field.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.bytes[13]
    }

    /// Returns the window size field.
    #[inline]
    pub fn window_size(&self) -> u16 {
        ((self.bytes[14] as u16) << 8) | (self.bytes[15] as u16)
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        ((self.bytes[16] as u16) << 8) | (self.bytes[17] as u16)
    }

    /// Returns the urgent pointer field.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        ((self.bytes[18] as u16) << 8) | (self.bytes[19] as u16)
    }

    /// Returns the header length in bytes by multiplying the data offset.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.data_offset() as usize * 4
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
}

impl<'a> fmt::Debug for TcpReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TcpSegment")
            .field("src_port", &self.src_port())
            .field("dest_port", &self.dest_port())
            .field("sequence_number", &self.sequence_number())
            .field("acknowledgment_number", &self.ack_number())
            .field("data_offset", &self.data_offset())
            .field("reserved", &self.reserved())
            .field("flags", &self.flags())
            .field("window_size", &self.window_size())
            .field("checksum", &self.checksum())
            .field("urgent_pointer", &self.urgent_pointer())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0u8; 40];

        // Random values.
        let src_ip = [192, 168, 1, 1];
        let dest_ip = [192, 168, 1, 2];
        let src_port = 12345;
        let dest_port = 54321;
        let sequence_number = 12345;
        let acknowledgment_number = 54321;
        let reserved = 10;
        let data_offset = 5;
        let flags = 2;
        let window_size = 1024;
        let urgent_pointer = 5;

        // Create a TCP packet writer.
        let mut writer = TcpWriter::new(&mut bytes).unwrap();

        // Set the TCP header fields.
        writer.set_src_port(src_port);
        writer.set_dest_port(dest_port);
        writer.set_sequence_number(sequence_number);
        writer.set_ack_number(acknowledgment_number);
        writer.set_reserved(reserved);
        writer.set_data_offset(data_offset);
        writer.set_flags(flags);
        writer.set_window_size(window_size);
        writer.set_urgent_pointer(urgent_pointer);
        writer.set_checksum(&src_ip, &dest_ip);

        // Create a TCP packet reader.
        let reader = TcpReader::new(&bytes).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(reader.src_port(), src_port);
        assert_eq!(reader.dest_port(), dest_port);
        assert_eq!(reader.sequence_number(), sequence_number);
        assert_eq!(reader.ack_number(), acknowledgment_number);
        assert_eq!(reader.reserved(), reserved);
        assert_eq!(reader.data_offset(), data_offset);
        assert_eq!(reader.flags(), flags);
        assert_eq!(reader.window_size(), window_size);
        assert_eq!(reader.urgent_pointer(), urgent_pointer);
    }
}
