use crate::misc::{to_hex_string, IpFormatter};
use core::{fmt, str::from_utf8};

/// The length of an ARP header in bytes.
pub const ARP_HEADER_LENGTH: usize = 28;

/// Represents an ARP header.
pub struct ArpBuilder<'a> {
    pub data: &'a mut [u8],
}

impl<'a> ArpBuilder<'a> {
    /// Creates a new `Arp` from the given slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < ARP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ARP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        ARP_HEADER_LENGTH
    }

    /// Sets the hardware type field.
    ///
    /// Specifies the type of hardware used for the network (e.g. Ethernet).
    #[inline]
    pub fn set_htype(&mut self, hardware_type: u16) {
        self.data[0] = (hardware_type >> 8) as u8;
        self.data[1] = hardware_type as u8;
    }

    /// Sets the protocol type field.
    ///
    /// Specifies the type of protocol address (e.g. IPv4).
    #[inline]
    pub fn set_ptype(&mut self, protocol_type: u16) {
        self.data[2] = (protocol_type >> 8) as u8;
        self.data[3] = protocol_type as u8;
    }

    /// Sets the hardware length field.
    ///
    /// Specifies the length of the hardware address in bytes.
    #[inline]
    pub fn set_hlen(&mut self, hardware_address_length: u8) {
        self.data[4] = hardware_address_length;
    }

    /// Sets the protocol length field.
    ///
    /// Specifies the length of the protocol address in bytes.
    #[inline]
    pub fn set_plen(&mut self, protocol_address_length: u8) {
        self.data[5] = protocol_address_length;
    }

    /// Sets the operation field.
    ///
    /// Specifies the operation being performed (e.g. request, reply).
    #[inline]
    pub fn set_oper(&mut self, operation: u16) {
        self.data[6] = (operation >> 8) as u8;
        self.data[7] = operation as u8;
    }

    /// Sets the sender hardware address field.
    ///
    /// Specifies the hardware address of the sender.
    #[inline]
    pub fn set_sha(&mut self, sender_hardware_address: &[u8; 6]) {
        self.data[8] = sender_hardware_address[0];
        self.data[9] = sender_hardware_address[1];
        self.data[10] = sender_hardware_address[2];
        self.data[11] = sender_hardware_address[3];
        self.data[12] = sender_hardware_address[4];
        self.data[13] = sender_hardware_address[5];
    }

    /// Sets the sender protocol address field.
    ///
    /// Specifies the protocol address of the sender.
    #[inline]
    pub fn set_spa(&mut self, sender_protocol_address: &[u8; 4]) {
        self.data[14] = sender_protocol_address[0];
        self.data[15] = sender_protocol_address[1];
        self.data[16] = sender_protocol_address[2];
        self.data[17] = sender_protocol_address[3];
    }

    /// Sets the target hardware address field.
    ///
    /// Specifies the hardware address of the receiver.
    #[inline]
    pub fn set_tha(&mut self, target_hardware_address: &[u8; 6]) {
        self.data[18] = target_hardware_address[0];
        self.data[19] = target_hardware_address[1];
        self.data[20] = target_hardware_address[2];
        self.data[21] = target_hardware_address[3];
        self.data[22] = target_hardware_address[4];
        self.data[23] = target_hardware_address[5];
    }

    /// Sets the target protocol address field.
    ///
    /// Specifies the protocol address of the receiver.
    #[inline]
    pub fn set_tpa(&mut self, target_protocol_address: &[u8; 4]) {
        self.data[24] = target_protocol_address[0];
        self.data[25] = target_protocol_address[1];
        self.data[26] = target_protocol_address[2];
        self.data[27] = target_protocol_address[3];
    }
}

#[derive(PartialEq)]
pub struct ArpParser<'a> {
    pub data: &'a [u8],
}

impl<'a> ArpParser<'a> {
    /// Creates a new `Arp` from the given slice.
    #[inline]
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < ARP_HEADER_LENGTH {
            return Err("Slice is too short to contain an ARP header.");
        }

        Ok(Self { data })
    }

    /// Returns the hardware type field.
    ///
    /// Specifies the type of hardware used for the network (e.g. Ethernet).
    #[inline]
    pub fn htype(&self) -> u16 {
        ((self.data[0] as u16) << 8) | (self.data[1] as u16)
    }

    /// Returns the protocol type field.
    ///
    /// Specifies the type of protocol address (e.g. IPv4).
    #[inline]
    pub fn ptype(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }

    /// Returns the hardware length field.
    ///
    /// Specifies the length of the hardware address in bytes.
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.data[4]
    }

    /// Returns the protocol length field.
    ///
    /// Specifies the length of the protocol address in bytes.
    #[inline]
    pub fn plen(&self) -> u8 {
        self.data[5]
    }

    /// Returns the operation field.
    ///
    /// Specifies the operation being performed (e.g. request, reply).
    #[inline]
    pub fn oper(&self) -> u16 {
        ((self.data[6] as u16) << 8) | (self.data[7] as u16)
    }

    /// Returns the sender hardware address field.
    ///
    /// Specifies the hardware address of the sender.
    #[inline]
    pub fn sha(&self) -> &[u8] {
        &self.data[8..14]
    }

    /// Returns the sender protocol address field.
    ///
    /// Specifies the protocol address of the sender.
    #[inline]
    pub fn spa(&self) -> &[u8] {
        &self.data[14..18]
    }

    /// Returns the target hardware address field.
    ///
    /// Specifies the hardware address of the receiver
    #[inline]
    pub fn tha(&self) -> &[u8] {
        &self.data[18..24]
    }

    /// Returns the target protocol address field.
    ///
    /// Specifies the protocol address of the receiver.
    #[inline]
    pub fn tpa(&self) -> &[u8] {
        &self.data[24..28]
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ARP_HEADER_LENGTH
    }

    /// Returns a reference to the header.
    #[inline]
    pub fn header(&self) -> &'a [u8] {
        &self.data[..ARP_HEADER_LENGTH]
    }

    /// Returns a reference to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[ARP_HEADER_LENGTH..]
    }
}

impl fmt::Debug for ArpParser<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sender_ip = self.spa();
        let target_ip = self.tpa();
        let mut sha_buf = [0u8; 18];
        let sha_len = to_hex_string(self.sha(), &mut sha_buf);
        let sha_hex = from_utf8(&sha_buf[..sha_len]).unwrap();
        let mut tha_buf = [0u8; 18];
        let tha_len = to_hex_string(self.tha(), &mut tha_buf);
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
        // Raw packet data.
        let mut data = [0; 28];

        // Create a new ARP header from the raw data.
        let mut builder = ArpBuilder::new(&mut data).unwrap();

        // Set the ARP header fields.
        builder.set_htype(1);
        builder.set_ptype(2);
        builder.set_hlen(3);
        builder.set_plen(4);
        builder.set_oper(5);
        builder.set_sha(&[6, 7, 8, 9, 10, 11]);
        builder.set_spa(&[12, 13, 14, 15]);
        builder.set_tha(&[16, 17, 18, 19, 20, 21]);
        builder.set_tpa(&[22, 23, 24, 25]);

        let parser = ArpParser::new(&data).unwrap();

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(parser.ptype(), 2);
        assert_eq!(parser.htype(), 1);
        assert_eq!(parser.hlen(), 3);
        assert_eq!(parser.plen(), 4);
        assert_eq!(parser.oper(), 5);
        assert_eq!(parser.sha(), &[6, 7, 8, 9, 10, 11]);
        assert_eq!(parser.spa(), &[12, 13, 14, 15]);
        assert_eq!(parser.tha(), &[16, 17, 18, 19, 20, 21]);
        assert_eq!(parser.tpa(), &[22, 23, 24, 25]);
    }
}
