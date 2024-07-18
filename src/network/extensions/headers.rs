use super::{
    fragment::FragmentHeaderReader, options::OptionsHeaderReader, routing::RoutingHeaderReader,
};
use crate::misc::NextHeader;

// Note:
// The IPv6 specification is weird. Packets can chain extension headers together.
// The next header field points to the next extension header in the chain.
// The last extension header in the chain points to the actual encapsulated payload (e.g. TCP).
// You may also encounter packets with multiple IPv6 headers (e.g. IPv6-in-IPv6).
// In that case you have to use the last IPv6 header for the pseudo header checksum.
// Using the outer IPv6 headers will result in a wrong checksum calculation.
// Also, it seems like there is no actual limit to the number of headers:
// RFC 6564: "There can be an arbitrary number of extension headers."

/// Contains all present extension headers in an IPv6 packet.
///
/// Each extension header is optional and should appear only once.
///
/// Except the Destination Options header, which may occur twice.
#[derive(Debug)]
pub struct ExtensionHeaders<'a> {
    pub hop_by_hop: Option<OptionsHeaderReader<'a>>,
    pub routing: Option<RoutingHeaderReader<'a>>,
    pub fragment: Option<FragmentHeaderReader<'a>>,
    pub destination: Option<OptionsHeaderReader<'a>>,
}

impl<'a> ExtensionHeaders<'a> {
    /// Parses the extension headers from the given byte slice.
    ///
    /// They are chained together through the next header field.
    ///
    /// Thus, we need to loop through them all to run down the chain.
    #[inline]
    pub fn new(bytes: &'a [u8], next_header: u8) -> Result<Option<Self>, &'static str> {
        let mut next_header = next_header;
        let mut bytes = bytes;

        let mut headers = Self {
            hop_by_hop: None,
            routing: None,
            fragment: None,
            destination: None,
        };

        loop {
            match NextHeader::from(next_header) {
                NextHeader::HopByHop => {
                    let reader = OptionsHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;
                    headers.hop_by_hop = Some(reader);
                }
                NextHeader::Routing => {
                    let reader = RoutingHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;
                    headers.routing = Some(reader);
                }
                NextHeader::Fragment => {
                    let reader = FragmentHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload();
                    headers.fragment = Some(reader);
                }
                NextHeader::Destination => {
                    let reader = OptionsHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;
                    headers.destination = Some(reader);
                }
                // We escape the loop if we don't recognize the next header.
                _ => break,
            }
        }

        if headers.hop_by_hop.is_none()
            && headers.routing.is_none()
            && headers.fragment.is_none()
            && headers.destination.is_none()
        {
            return Ok(None);
        }

        Ok(Some(headers))
    }

    /// Returns the total length of all present extension headers.
    #[inline]
    pub fn total_header_len(&self) -> usize {
        let mut total_len = 0;

        if let Some(hop_by_hop) = &self.hop_by_hop {
            total_len += hop_by_hop.header_len();
        }

        if let Some(routing) = &self.routing {
            total_len += routing.header_len();
        }

        if let Some(fragment) = &self.fragment {
            total_len += fragment.header_len();
        }

        if let Some(destination) = &self.destination {
            total_len += destination.header_len();
        }

        total_len
    }
}
