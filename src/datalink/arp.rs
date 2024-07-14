use crate::misc::{bytes_to_mac, IpFormatter};
use core::{fmt, str::from_utf8};

/// The length of an ARP header in bytes.
pub const ARP_HEADER_LENGTH: usize = 28;

/// Writes ARP header fields.
pub struct ArpWriter<'a> {
    pub bytes: &'a mut [u8],
}

impl<'a> ArpWriter<'a> {
    /// Creates a new `ArpWriter` from the given slice.
    #[inline]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ARP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ARP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ARP_HEADER_LENGTH
    }

    /// Sets the hardware type field.
    ///
    /// Specifies the type of hardware used for the network (e.g. Ethernet).
    #[inline]
    pub fn set_htype(&mut self, hardware_type: u16) {
        self.bytes[0] = (hardware_type >> 8) as u8;
        self.bytes[1] = hardware_type as u8;
    }

    /// Sets the protocol type field.
    ///
    /// Specifies the type of protocol address (e.g. IPv4).
    #[inline]
    pub fn set_ptype(&mut self, protocol_type: u16) {
        self.bytes[2] = (protocol_type >> 8) as u8;
        self.bytes[3] = protocol_type as u8;
    }

    /// Sets the hardware length field.
    ///
    /// Specifies the length of the hardware address in bytes.
    #[inline]
    pub fn set_hlen(&mut self, hardware_address_length: u8) {
        self.bytes[4] = hardware_address_length;
    }

    /// Sets the protocol length field.
    ///
    /// Specifies the length of the protocol address in bytes.
    #[inline]
    pub fn set_plen(&mut self, protocol_address_length: u8) {
        self.bytes[5] = protocol_address_length;
    }

    /// Sets the operation field.
    ///
    /// Specifies the operation being performed (e.g. request, reply).
    #[inline]
    pub fn set_oper(&mut self, operation: u16) {
        self.bytes[6] = (operation >> 8) as u8;
        self.bytes[7] = operation as u8;
    }

    /// Sets the sender hardware address field.
    ///
    /// Specifies the hardware address of the sender.
    #[inline]
    pub fn set_sha(&mut self, sender_hardware_address: &[u8; 6]) {
        self.bytes[8] = sender_hardware_address[0];
        self.bytes[9] = sender_hardware_address[1];
        self.bytes[10] = sender_hardware_address[2];
        self.bytes[11] = sender_hardware_address[3];
        self.bytes[12] = sender_hardware_address[4];
        self.bytes[13] = sender_hardware_address[5];
    }

    /// Sets the sender protocol address field.
    ///
    /// Specifies the protocol address of the sender.
    #[inline]
    pub fn set_spa(&mut self, sender_protocol_address: &[u8; 4]) {
        self.bytes[14] = sender_protocol_address[0];
        self.bytes[15] = sender_protocol_address[1];
        self.bytes[16] = sender_protocol_address[2];
        self.bytes[17] = sender_protocol_address[3];
    }

    /// Sets the target hardware address field.
    ///
    /// Specifies the hardware address of the receiver.
    #[inline]
    pub fn set_tha(&mut self, target_hardware_address: &[u8; 6]) {
        self.bytes[18] = target_hardware_address[0];
        self.bytes[19] = target_hardware_address[1];
        self.bytes[20] = target_hardware_address[2];
        self.bytes[21] = target_hardware_address[3];
        self.bytes[22] = target_hardware_address[4];
        self.bytes[23] = target_hardware_address[5];
    }

    /// Sets the target protocol address field.
    ///
    /// Specifies the protocol address of the receiver.
    #[inline]
    pub fn set_tpa(&mut self, target_protocol_address: &[u8; 4]) {
        self.bytes[24] = target_protocol_address[0];
        self.bytes[25] = target_protocol_address[1];
        self.bytes[26] = target_protocol_address[2];
        self.bytes[27] = target_protocol_address[3];
    }
}

/// Reads ARP header fields.
#[derive(PartialEq)]
pub struct ArpReader<'a> {
    pub bytes: &'a [u8],
}

impl<'a> ArpReader<'a> {
    /// Creates a new `ArpReader` from the given slice.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < ARP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ARP header.");
        }

        Ok(Self { bytes })
    }

    /// Returns the hardware type field.
    ///
    /// Specifies the type of hardware used for the network (e.g. Ethernet).
    #[inline]
    pub fn htype(&self) -> u16 {
        ((self.bytes[0] as u16) << 8) | (self.bytes[1] as u16)
    }

    /// Returns the protocol type field.
    ///
    /// Specifies the type of protocol address (e.g. IPv4).
    #[inline]
    pub fn ptype(&self) -> u16 {
        ((self.bytes[2] as u16) << 8) | (self.bytes[3] as u16)
    }

    /// Returns the hardware length field.
    ///
    /// Specifies the length of the hardware address in bytes.
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.bytes[4]
    }

    /// Returns the protocol length field.
    ///
    /// Specifies the length of the protocol address in bytes.
    #[inline]
    pub fn plen(&self) -> u8 {
        self.bytes[5]
    }

    /// Returns the operation field.
    ///
    /// Specifies the operation being performed (e.g. request, reply).
    #[inline]
    pub fn oper(&self) -> u16 {
        ((self.bytes[6] as u16) << 8) | (self.bytes[7] as u16)
    }

    /// Returns the sender hardware address field.
    ///
    /// Specifies the hardware address of the sender.
    #[inline]
    pub fn sha(&self) -> &[u8] {
        &self.bytes[8..14]
    }

    /// Returns the sender protocol address field.
    ///
    /// Specifies the protocol address of the sender.
    #[inline]
    pub fn spa(&self) -> &[u8] {
        &self.bytes[14..18]
    }

    /// Returns the target hardware address field.
    ///
    /// Specifies the hardware address of the receiver
    #[inline]
    pub fn tha(&self) -> &[u8] {
        &self.bytes[18..24]
    }

    /// Returns the target protocol address field.
    ///
    /// Specifies the protocol address of the receiver.
    #[inline]
    pub fn tpa(&self) -> &[u8] {
        &self.bytes[24..28]
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ARP_HEADER_LENGTH
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..ARP_HEADER_LENGTH]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[ARP_HEADER_LENGTH..]
    }
}

impl fmt::Debug for ArpReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sender_ip = self.spa();
        let target_ip = self.tpa();
        let mut sha_buf = [0u8; 18];
        let sha_len = bytes_to_mac(self.sha(), &mut sha_buf);
        let sha_hex = from_utf8(&sha_buf[..sha_len]).unwrap();
        let mut tha_buf = [0u8; 18];
        let tha_len = bytes_to_mac(self.tha(), &mut tha_buf);
        let tha_hex = from_utf8(&tha_buf[..tha_len]).unwrap();
        f.debug_struct("Arp")
            .field("hardware_type", &self.htype())
            .field("protocol_type", &self.ptype())
            .field("hardware_address_length", &self.hlen())
            .field("protocol_address_length", &self.plen())
            .field("operation", &self.oper())
            .field("sender_hardware_address", &sha_hex)
            .field("sender_protocol_address", &IpFormatter(sender_ip))
            .field("target_hardware_address", &tha_hex)
            .field("target_protocol_address", &IpFormatter(target_ip))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters_and_setters() {
        // Raw packet.
        let mut bytes = [0; 28];

        // Create an ARP writer.
        let mut writer = ArpWriter::new(&mut bytes).unwrap();

        // Set the ARP header fields.
        writer.set_htype(1);
        writer.set_ptype(2);
        writer.set_hlen(3);
        writer.set_plen(4);
        writer.set_oper(5);
        writer.set_sha(&[6, 7, 8, 9, 10, 11]);
        writer.set_spa(&[12, 13, 14, 15]);
        writer.set_tha(&[16, 17, 18, 19, 20, 21]);
        writer.set_tpa(&[22, 23, 24, 25]);

        // Create an ARP reader.
        let reader = ArpReader::new(&bytes).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(reader.ptype(), 2);
        assert_eq!(reader.htype(), 1);
        assert_eq!(reader.hlen(), 3);
        assert_eq!(reader.plen(), 4);
        assert_eq!(reader.oper(), 5);
        assert_eq!(reader.sha(), &[6, 7, 8, 9, 10, 11]);
        assert_eq!(reader.spa(), &[12, 13, 14, 15]);
        assert_eq!(reader.tha(), &[16, 17, 18, 19, 20, 21]);
        assert_eq!(reader.tpa(), &[22, 23, 24, 25]);
    }
}
