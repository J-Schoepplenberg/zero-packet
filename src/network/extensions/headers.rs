use super::{
    authentication::AuthenticationHeaderReader, fragment::FragmentHeaderReader,
    options::OptionsHeaderReader, routing::RoutingHeaderReader,
};
use crate::misc::NextHeader;

// Note:
// According to RFC 8200 packets should not contain more than one occurence of an extension header.
// An exception is the Destination Options header, which may occur twice.
// However, IPv6 nodes have to be able to accept and process packets even if they contain any arbitrary
// number of extension headers. Which means that these packets are still valid, even though they should not exist.

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
    pub auth_header: Option<AuthenticationHeaderReader<'a>>,
    pub destination_1st: Option<OptionsHeaderReader<'a>>,
    pub destination_2nd: Option<OptionsHeaderReader<'a>>,
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
            auth_header: None,
            destination_1st: None,
            destination_2nd: None,
        };

        loop {
            match NextHeader::from(next_header) {
                NextHeader::HopByHop => {
                    if headers.hop_by_hop.is_some() {
                        break;
                    }

                    if headers.routing.is_some()
                        || headers.fragment.is_some()
                        || headers.destination_1st.is_some()
                        || headers.destination_2nd.is_some()
                    {
                        return Err("If Hop-by-Hop Options is present, then it must be the first extension header.");
                    }

                    let reader = OptionsHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;
                    headers.hop_by_hop = Some(reader);
                }
                NextHeader::Routing => {
                    if headers.routing.is_some() {
                        break;
                    }

                    let reader = RoutingHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;
                    headers.routing = Some(reader);
                }
                NextHeader::Fragment => {
                    if headers.fragment.is_some() {
                        break;
                    }

                    let reader = FragmentHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload();
                    headers.fragment = Some(reader);
                }
                NextHeader::AuthHeader => {
                    if headers.auth_header.is_some() {
                        break;
                    }

                    let reader = AuthenticationHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;
                    headers.auth_header = Some(reader);
                }
                NextHeader::Destination => {
                    if headers.destination_2nd.is_some() {
                        break;
                    }

                    let reader = OptionsHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    bytes = reader.payload()?;

                    if headers.destination_1st.is_none() {
                        headers.destination_1st = Some(reader);
                    } else {
                        headers.destination_2nd = Some(reader);
                    }
                }
                // We escape the loop if we don't recognize the next header.
                _ => break,
            }
        }

        if headers.hop_by_hop.is_none()
            && headers.routing.is_none()
            && headers.fragment.is_none()
            && headers.auth_header.is_none()
            && headers.destination_1st.is_none()
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

        if let Some(auth_header) = &self.auth_header {
            total_len += auth_header.header_len();
        }

        if let Some(destination) = &self.destination_1st {
            total_len += destination.header_len();
        }

        if let Some(destination) = &self.destination_2nd {
            total_len += destination.header_len();
        }

        total_len
    }
}
