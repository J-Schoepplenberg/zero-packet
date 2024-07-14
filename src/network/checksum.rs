/// Calculates the internet checksum for error checking.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc1071.>.
#[inline]
pub fn internet_checksum(data: &[u8], accumulator: u32) -> u16 {
    let mut sum = accumulator;
    let mut count = data.len();
    let mut i = 0;

    // Sums up 16-bit words.
    while count > 1 {
        sum += u32::from(data[i]) << 8 | u32::from(data[i + 1]);
        i += 2;
        count -= 2;
    }

    // Handle the case of an odd number of bytes.
    if count > 0 {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement of the sum.
    !sum as u16
}

/// Sums up the IP pseudo header for the checksum calculation.
#[inline]
pub fn ipv4_pseudo_header(src_ip: &[u8; 4], dest_ip: &[u8; 4], protocol: u8, length: usize) -> u32 {
    let mut pseudo_header = 0u32;

    pseudo_header += u32::from(src_ip[0]) << 8 | u32::from(src_ip[1]);
    pseudo_header += u32::from(src_ip[2]) << 8 | u32::from(src_ip[3]);
    pseudo_header += u32::from(dest_ip[0]) << 8 | u32::from(dest_ip[1]);
    pseudo_header += u32::from(dest_ip[2]) << 8 | u32::from(dest_ip[3]);
    pseudo_header += u32::from(protocol);
    pseudo_header += length as u32;

    pseudo_header
}

/// Sums up the IP pseudo header for the checksum calculation.
#[inline]
pub fn ipv6_pseudo_header(
    src_addr: &[u8; 16],
    dest_addr: &[u8; 16],
    protocol: u8,
    length: usize,
) -> u32 {
    let mut pseudo_header = 0u32;

    pseudo_header += u32::from(src_addr[0]) << 8 | u32::from(src_addr[1]);
    pseudo_header += u32::from(src_addr[2]) << 8 | u32::from(src_addr[3]);
    pseudo_header += u32::from(src_addr[4]) << 8 | u32::from(src_addr[5]);
    pseudo_header += u32::from(src_addr[6]) << 8 | u32::from(src_addr[7]);
    pseudo_header += u32::from(src_addr[8]) << 8 | u32::from(src_addr[9]);
    pseudo_header += u32::from(src_addr[10]) << 8 | u32::from(src_addr[11]);
    pseudo_header += u32::from(src_addr[12]) << 8 | u32::from(src_addr[13]);
    pseudo_header += u32::from(src_addr[14]) << 8 | u32::from(src_addr[15]);
    pseudo_header += u32::from(dest_addr[0]) << 8 | u32::from(dest_addr[1]);
    pseudo_header += u32::from(dest_addr[2]) << 8 | u32::from(dest_addr[3]);
    pseudo_header += u32::from(dest_addr[4]) << 8 | u32::from(dest_addr[5]);
    pseudo_header += u32::from(dest_addr[6]) << 8 | u32::from(dest_addr[7]);
    pseudo_header += u32::from(dest_addr[8]) << 8 | u32::from(dest_addr[9]);
    pseudo_header += u32::from(dest_addr[10]) << 8 | u32::from(dest_addr[11]);
    pseudo_header += u32::from(dest_addr[12]) << 8 | u32::from(dest_addr[13]);
    pseudo_header += u32::from(dest_addr[14]) << 8 | u32::from(dest_addr[15]);
    pseudo_header += length as u32;
    pseudo_header += u32::from(protocol);

    pseudo_header
}

/// Verifies the checksum field.
#[inline]
pub fn verify_internet_checksum(data: &[u8], accumulator: u32) -> bool {
    internet_checksum(data, accumulator) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_zeros() {
        let data = [0u8; 8];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 65535);
    }

    #[test]
    fn test_checksum_non_zeros() {
        let data = [255u8; 8];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0);
    }

    #[test]
    fn test_checksum_so() {
        let data = [
            0x45, 0x00, 0x00, 0x34, 0x5f, 0x7c, 0x40, 0x00, 0x40, 0x06, 0xc0, 0xa8, 0xb2, 0x14,
            0xc6, 0xfc, 0xce, 0x19,
        ];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0xd374);
    }

    #[test]
    fn test_checksum_wkpda() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0xb861);
    }

    #[test]
    fn test_checksum_nf() {
        let data = [0x01, 0x00, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0x210e);
    }

    #[test]
    fn test_verify_checksum() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert!(verify_internet_checksum(&data, 0));
    }
}
