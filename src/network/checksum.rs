/// Calculates the checksum field.
///
/// Mandatory for IPv4 protocol.
///
/// See: https://datatracker.ietf.org/doc/html/rfc1071.
#[inline]
pub fn internet_checksum(data: &[u8], accumulator: u32) -> u16 {
    let mut sum = accumulator;
    let mut i = 0;

    while i < data.len() {
        sum += u32::from(data[i]) << 8 | u32::from(data[i + 1]);
        i += 2;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Sums up the IP pseudo header for the checksum of TCP and UDP.
/// 
/// These fields are not actually part of the TCP or UDP header.
#[inline]
pub fn pseudo_header(src_ip: &[u8; 4], dest_ip: &[u8; 4], protocol: u8, length: usize) -> u32 {
    let mut pseudo_header = 0u32;

    pseudo_header += u32::from(src_ip[0]) << 8 | u32::from(src_ip[1]);
    pseudo_header += u32::from(src_ip[2]) << 8 | u32::from(src_ip[3]);
    pseudo_header += u32::from(dest_ip[0]) << 8 | u32::from(dest_ip[1]);
    pseudo_header += u32::from(dest_ip[2]) << 8 | u32::from(dest_ip[3]);
    pseudo_header += u32::from(protocol);
    pseudo_header += length as u32;

    pseudo_header
}
