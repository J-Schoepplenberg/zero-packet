use core::fmt;

use crate::utils::to_hex_string;

/// Represents an ARP header.
pub struct Arp<'a> {
    pub data: &'a mut [u8],
}

impl<'a> Arp<'a> {
    /// The minimum length of an ARP header in bytes.
    pub const HEADER_LENGTH: usize = 28;

    /// Creates a new `Arp` from the given slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < Self::HEADER_LENGTH {
            return Err("Slice is too short to contain an ARP header.");
        }

        Ok(Self { data })
    }

    /// Returns the header length in bytes.
    #[inline]
    pub fn header_length(&self) -> usize {
        Self::HEADER_LENGTH
    }

    /// Returns the hardware type field.
    ///
    /// Specifies the type of hardware used for the network (e.g. Ethernet).
    #[inline]
    pub fn get_htype(&self) -> u16 {
        ((self.data[0] as u16) << 8) | (self.data[1] as u16)
    }

    /// Returns the protocol type field.
    ///
    /// Specifies the type of protocol address (e.g. IPv4).
    #[inline]
    pub fn get_ptype(&self) -> u16 {
        ((self.data[2] as u16) << 8) | (self.data[3] as u16)
    }

    /// Returns the hardware length field.
    ///
    /// Specifies the length of the hardware address in bytes.
    #[inline]
    pub fn get_hlen(&self) -> u8 {
        self.data[4]
    }

    /// Returns the protocol length field.
    ///
    /// Specifies the length of the protocol address in bytes.
    #[inline]
    pub fn get_plen(&self) -> u8 {
        self.data[5]
    }

    /// Returns the operation field.
    ///
    /// Specifies the operation being performed (e.g. request, reply).
    #[inline]
    pub fn get_oper(&self) -> u16 {
        ((self.data[6] as u16) << 8) | (self.data[7] as u16)
    }

    /// Returns the sender hardware address field.
    ///
    /// Specifies the hardware address of the sender.
    #[inline]
    pub fn get_sha(&self) -> &[u8] {
        &self.data[8..14]
    }

    /// Returns the sender protocol address field.
    ///
    /// Specifies the protocol address of the sender.
    #[inline]
    pub fn get_spa(&self) -> &[u8] {
        &self.data[14..18]
    }

    /// Returns the target hardware address field.
    ///
    /// Specifies the hardware address of the receiver
    #[inline]
    pub fn get_tha(&self) -> &[u8] {
        &self.data[18..24]
    }

    /// Returns the target protocol address field.
    ///
    /// Specifies the protocol address of the receiver.
    #[inline]
    pub fn get_tpa(&self) -> &[u8] {
        &self.data[24..28]
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

impl fmt::Debug for Arp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sender_ip = self.get_spa();
        let target_ip = self.get_tpa();
        let sender_formatted = format!(
            "{}.{}.{}.{}",
            sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]
        );
        let target_formatted = format!(
            "{}.{}.{}.{}",
            target_ip[0], target_ip[1], target_ip[2], target_ip[3]
        );
        f.debug_struct("Arp")
            .field("hardware_type", &self.get_htype())
            .field("protocol_type", &self.get_ptype())
            .field("hardware_address_length", &self.get_hlen())
            .field("protocol_address_length", &self.get_plen())
            .field("operation", &self.get_oper())
            .field("sender_hardware_address", &to_hex_string(self.get_sha()))
            .field("sender_protocol_address", &sender_formatted)
            .field("target_hardware_address", &to_hex_string(self.get_tha()))
            .field("target_protocol_address", &target_formatted)
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
        let mut arp = Arp::new(&mut data).unwrap();

        // Set the ARP header fields.
        arp.set_htype(1);
        arp.set_ptype(2);
        arp.set_hlen(3);
        arp.set_plen(4);
        arp.set_oper(5);
        arp.set_sha(&[6, 7, 8, 9, 10, 11]);
        arp.set_spa(&[12, 13, 14, 15]);
        arp.set_tha(&[16, 17, 18, 19, 20, 21]);
        arp.set_tpa(&[22, 23, 24, 25]);

        // Ensure the fields are set and retrieved correctly.
        assert_eq!(arp.get_htype(), 1);
        assert_eq!(arp.get_ptype(), 2);
        assert_eq!(arp.get_hlen(), 3);
        assert_eq!(arp.get_plen(), 4);
        assert_eq!(arp.get_oper(), 5);
        assert_eq!(arp.get_sha(), &[6, 7, 8, 9, 10, 11]);
        assert_eq!(arp.get_spa(), &[12, 13, 14, 15]);
        assert_eq!(arp.get_tha(), &[16, 17, 18, 19, 20, 21]);
        assert_eq!(arp.get_tpa(), &[22, 23, 24, 25]);

        println!("{:?}", arp);
    }
}
