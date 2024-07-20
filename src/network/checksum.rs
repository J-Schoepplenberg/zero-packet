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

/// Verifies the checksum field.
#[inline]
pub fn verify_internet_checksum(data: &[u8], accumulator: u32) -> bool {
    internet_checksum(data, accumulator) == 0
}

/// Trait to sum up the IPv4/v6 pseudo header.
pub trait PseudoHeader {
    /// Sums up the addresses for the checksum calculation.
    fn sum(&self) -> u32;
}

impl PseudoHeader for [u8; 4] {
    #[inline]
    fn sum(&self) -> u32 {
        (u32::from(self[0]) << 8 | u32::from(self[1]))
            + (u32::from(self[2]) << 8 | u32::from(self[3]))
    }
}

impl PseudoHeader for [u8; 16] {
    #[inline]
    fn sum(&self) -> u32 {
        (u32::from(self[0]) << 8 | u32::from(self[1]))
            + (u32::from(self[2]) << 8 | u32::from(self[3]))
            + (u32::from(self[4]) << 8 | u32::from(self[5]))
            + (u32::from(self[6]) << 8 | u32::from(self[7]))
            + (u32::from(self[8]) << 8 | u32::from(self[9]))
            + (u32::from(self[10]) << 8 | u32::from(self[11]))
            + (u32::from(self[12]) << 8 | u32::from(self[13]))
            + (u32::from(self[14]) << 8 | u32::from(self[15]))
    }
}

/// Sums up the IPv4/v6 pseudo header for the checksum calculation.
#[inline]
pub fn pseudo_header<T: PseudoHeader>(src: &T, dest: &T, protocol: u8, length: usize) -> u32 {
    src.sum() + dest.sum() + u32::from(protocol) + length as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zeros() {
        let data = [0u8; 8];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 65535);
    }

    #[test]
    fn checksum_non_zeros() {
        let data = [255u8; 8];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0);
    }

    #[test]
    fn checksum_so() {
        let data = [
            0x45, 0x00, 0x00, 0x34, 0x5f, 0x7c, 0x40, 0x00, 0x40, 0x06, 0xc0, 0xa8, 0xb2, 0x14,
            0xc6, 0xfc, 0xce, 0x19,
        ];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0xd374);
    }

    #[test]
    fn checksum_wkpda() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0xb861);
    }

    #[test]
    fn checksum_nf() {
        let data = [0x01, 0x00, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = internet_checksum(&data, 0);
        assert_eq!(checksum, 0x210e);
    }

    #[test]
    fn verify_checksum() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert!(verify_internet_checksum(&data, 0));
    }

    #[test]
    fn pseudo_sum() {
        let src_ip = [192, 168, 0, 1];
        let dest_ip = [192, 168, 0, 199];
        let protocol = 6;
        let length = 20;
        let sum = pseudo_header(&src_ip, &dest_ip, protocol, length);
        assert_eq!(sum, 98866);
    }
}
