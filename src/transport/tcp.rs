use crate::network::checksum::{internet_checksum, pseudo_header};
use core::fmt;

/// Represents a TCP segment.
pub struct TcpSegment<'a> {
    pub data: &'a mut [u8],
}

impl<'a> TcpSegment<'a> {
    /// The minimum length of a TCP header in bytes.
    const HEADER_LENGTH: usize = 20;

    /// Creates a new `TcpSegment` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < Self::HEADER_LENGTH {
            return Err("Slice is too short to contain a TCP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        self.get_data_offset() as usize * 4
    }

    /// Returns the source port field.
    #[inline]
    pub fn get_src_port(&self) -> u16 {
        ((self.data[0] as u16) << 8) | (self.data[1] as u16)
    }

    /// Returns the destination port field.
    #[inline]
    pub fn get_dest_port(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }

    /// Returns the sequence number field.
    #[inline]
    pub fn get_sequence_number(&self) -> u32 {
        ((self.data[4] as u32) << 24)
            | ((self.data[5] as u32) << 16)
            | ((self.data[6] as u32) << 8)
            | (self.data[7] as u32)
    }

    /// Returns the acknowledgment number field.
    #[inline]
    pub fn get_acknowledgment_number(&self) -> u32 {
        ((self.data[8] as u32) << 24)
            | ((self.data[9] as u32) << 16)
            | ((self.data[10] as u32) << 8)
            | (self.data[11] as u32)
    }

    /// Returns the data offset field.
    #[inline]
    pub fn get_data_offset(&self) -> u8 {
        self.data[12] >> 4
    }

    /// Returns the reserved field.
    #[inline]
    pub fn get_reserved(&self) -> u8 {
        self.data[12] & 0x0F
    }

    /// Returns the flags field.
    #[inline]
    pub fn get_flags(&self) -> u8 {
        self.data[13]
    }

    /// Returns the window size field.
    #[inline]
    pub fn get_window_size(&self) -> u16 {
        ((self.data[14] as u16) << 8) | (self.data[15] as u16)
    }

    /// Returns the checksum field.
    #[inline]
    pub fn get_checksum(&self) -> u16 {
        ((self.data[16] as u16) << 8) | (self.data[17] as u16)
    }

    /// Returns the urgent pointer field.
    #[inline]
    pub fn get_urgent_pointer(&self) -> u16 {
        ((self.data[18] as u16) << 8) | (self.data[19] as u16)
    }

    /// Sets the source port field.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.data[0] = (src_port >> 8) as u8;
        self.data[1] = (src_port & 0xFF) as u8;
    }

    /// Sets the destination port field.
    #[inline]
    pub fn set_dest_port(&mut self, dest_port: u16) {
        self.data[2] = (dest_port >> 8) as u8;
        self.data[3] = (dest_port & 0xFF) as u8;
    }

    /// Sets the sequence number field.
    #[inline]
    pub fn set_sequence_number(&mut self, sequence_number: u32) {
        self.data[4] = (sequence_number >> 24) as u8;
        self.data[5] = (sequence_number >> 16) as u8;
        self.data[6] = (sequence_number >> 8) as u8;
        self.data[7] = (sequence_number & 0xFF) as u8;
    }

    /// Sets the acknowledgment number field.
    #[inline]
    pub fn set_acknowledgment_number(&mut self, acknowledgment_number: u32) {
        self.data[8] = (acknowledgment_number >> 24) as u8;
        self.data[9] = (acknowledgment_number >> 16) as u8;
        self.data[10] = (acknowledgment_number >> 8) as u8;
        self.data[11] = (acknowledgment_number & 0xFF) as u8;
    }

    /// Sets the data offset field.
    #[inline]
    pub fn set_data_offset(&mut self, data_offset: u8) {
        self.data[12] = (data_offset << 4) | (self.data[12] & 0x0f);
    }

    /// Sets the reserved field.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        self.data[12] = (self.data[12] & 0xf0) | (reserved & 0x0f);
    }

    /// Sets the flags field.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.data[13] = flags;
    }

    /// Sets the window size field.
    #[inline]
    pub fn set_window_size(&mut self, window_size: u16) {
        self.data[14] = (window_size >> 8) as u8;
        self.data[15] = (window_size & 0xFF) as u8;
    }

    /// Sets the urgent pointer field.
    #[inline]
    pub fn set_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.data[18] = (urgent_pointer >> 8) as u8;
        self.data[19] = (urgent_pointer & 0xFF) as u8;
    }

    /// Calculates the checksum field for error checking.
    ///
    /// Consists of the IP pseudo-header, TCP header and payload.
    #[inline]
    pub fn set_checksum(&mut self, src_ip: &[u8; 4], dest_ip: &[u8; 4]) {
        self.data[16] = 0;
        self.data[17] = 0;
        let pseudo_header = pseudo_header(src_ip, dest_ip, 6, self.data.len());
        let checksum = internet_checksum(&self.data, pseudo_header);
        self.data[16] = (checksum >> 8) as u8;
        self.data[17] = (checksum & 0xff) as u8;
    }
}

impl<'a> fmt::Debug for TcpSegment<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TcpSegment")
            .field("src_port", &self.get_src_port())
            .field("dest_port", &self.get_dest_port())
            .field("sequence_number", &self.get_sequence_number())
            .field("acknowledgment_number", &self.get_acknowledgment_number())
            .field("data_offset", &self.get_data_offset())
            .field("reserved", &self.get_reserved())
            .field("flags", &self.get_flags())
            .field("window_size", &self.get_window_size())
            .field("checksum", &self.get_checksum())
            .field("urgent_pointer", &self.get_urgent_pointer())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet data.
        let mut data = [0u8; 40];

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

        // Create a new TCP segment from the raw data.
        let mut tcp_segment = TcpSegment::new(&mut data).unwrap();
        tcp_segment.set_src_port(src_port);
        tcp_segment.set_dest_port(dest_port);
        tcp_segment.set_sequence_number(sequence_number);
        tcp_segment.set_acknowledgment_number(acknowledgment_number);
        tcp_segment.set_reserved(reserved);
        tcp_segment.set_data_offset(data_offset);
        tcp_segment.set_flags(flags);
        tcp_segment.set_window_size(window_size);
        tcp_segment.set_urgent_pointer(urgent_pointer);
        tcp_segment.set_checksum(&src_ip, &dest_ip);

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(tcp_segment.get_src_port(), src_port);
        assert_eq!(tcp_segment.get_dest_port(), dest_port);
        assert_eq!(tcp_segment.get_sequence_number(), sequence_number);
        assert_eq!(
            tcp_segment.get_acknowledgment_number(),
            acknowledgment_number
        );
        assert_eq!(tcp_segment.get_reserved(), reserved);
        assert_eq!(tcp_segment.get_data_offset(), data_offset);
        assert_eq!(tcp_segment.get_flags(), flags);
        assert_eq!(tcp_segment.get_window_size(), window_size);
        assert_eq!(tcp_segment.get_urgent_pointer(), urgent_pointer);
    }
}
