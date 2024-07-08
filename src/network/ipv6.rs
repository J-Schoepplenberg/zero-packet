pub struct IPv6Packet<'a> {
    pub data: &'a mut [u8],
}

impl<'a> IPv6Packet<'a> {
    /// The minimum length of an IPv6 header in bytes.
    const HEADER_LENGTH: usize = 40;

    /// Creates a new `IPv6Packet` from the given data slice.
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Result<Self, &'static str> {
        if data.len() < Self::HEADER_LENGTH {
            return Err("Slice is too short to contain an IPv6 header.");
        }

        Ok(Self { data })
    }
}
