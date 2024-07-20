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
    pub total_headers_len: usize,
    pub final_next_header: u8,
}

impl<'a> ExtensionHeaders<'a> {
    /// Creates a new `ExtensionHeaders`.
    #[inline]
    fn new() -> Self {
        Self {
            hop_by_hop: None,
            routing: None,
            fragment: None,
            auth_header: None,
            destination_1st: None,
            destination_2nd: None,
            total_headers_len: 0,
            final_next_header: 0,
        }
    }
    /// Parses the extension headers from the given byte slice.
    ///
    /// They are chained together through the next header field.
    ///
    /// Thus, we need to loop through them all to run down the chain.
    #[inline]
    pub fn parse(bytes: &'a [u8], next_header: u8) -> Result<Option<Self>, &'static str> {
        let mut headers = Self::new();

        let mut current_header = next_header;
        let mut current_bytes = bytes;

        while let Some((next_header, payload)) =
            headers.parse_next_header(current_header, current_bytes)?
        {
            current_header = next_header;
            current_bytes = payload;
        }

        if headers.is_empty() {
            Ok(None)
        } else {
            Ok(Some(headers))
        }
    }

    /// Parses the next extension header.
    #[inline]
    fn parse_next_header(
        &mut self,
        next_header: u8,
        bytes: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, &'static str> {
        match NextHeader::from(next_header) {
            NextHeader::HopByHop => self.parse_hop_by_hop_options(bytes),
            NextHeader::Routing => self.parse_routing_header(bytes),
            NextHeader::Fragment => self.parse_fragment_header(bytes),
            NextHeader::AuthHeader => self.parse_auth_header(bytes),
            NextHeader::Destination => self.parse_destination_options(bytes),
            _ => Ok(None),
        }
    }

    /// Parses the Hop-by-Hop Options extension header.
    #[inline]
    fn parse_hop_by_hop_options(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, &'static str> {
        if self.hop_by_hop.is_some() {
            return Ok(None);
        }

        if !self.is_empty() {
            return Err(
                "If Hop-by-Hop Options is present, then it must be the first extension header.",
            );
        }

        let reader = OptionsHeaderReader::new(bytes)?;
        let next_header = reader.next_header();
        let payload = reader.payload()?;

        self.total_headers_len += reader.header_len();
        self.final_next_header = next_header;
        self.hop_by_hop = Some(reader);

        Ok(Some((next_header, payload)))
    }

    /// Parses the Routing extension header.
    #[inline]
    fn parse_routing_header(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, &'static str> {
        if self.routing.is_some() {
            return Ok(None);
        }

        let reader = RoutingHeaderReader::new(bytes)?;
        let next_header = reader.next_header();
        let payload = reader.payload()?;

        self.total_headers_len += reader.header_len();
        self.final_next_header = next_header;
        self.routing = Some(reader);

        Ok(Some((next_header, payload)))
    }

    /// Parses the Fragment extension header.
    #[inline]
    fn parse_fragment_header(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, &'static str> {
        if self.fragment.is_some() {
            return Ok(None);
        }

        let reader = FragmentHeaderReader::new(bytes)?;
        let next_header = reader.next_header();
        let payload = reader.payload();

        self.total_headers_len += reader.header_len();
        self.final_next_header = next_header;
        self.fragment = Some(reader);

        Ok(Some((next_header, payload)))
    }

    /// Parses the Authentication Header extension header.
    #[inline]
    fn parse_auth_header(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, &'static str> {
        if self.auth_header.is_some() {
            return Ok(None);
        }

        let reader = AuthenticationHeaderReader::new(bytes)?;
        let next_header = reader.next_header();
        let payload = reader.payload()?;

        self.total_headers_len += reader.header_len();
        self.final_next_header = next_header;
        self.auth_header = Some(reader);

        Ok(Some((next_header, payload)))
    }

    /// Parses the Destination Options extension header.
    #[inline]
    fn parse_destination_options(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<Option<(u8, &'a [u8])>, &'static str> {
        if self.destination_2nd.is_some() {
            return Ok(None);
        }

        let reader = OptionsHeaderReader::new(bytes)?;
        let next_header = reader.next_header();
        let payload = reader.payload()?;

        self.total_headers_len += reader.header_len();
        self.final_next_header = next_header;

        if self.destination_1st.is_none() {
            self.destination_1st = Some(reader);
        } else {
            self.destination_2nd = Some(reader);
        }

        Ok(Some((next_header, payload)))
    }

    /// Returns if no extension headers are present.
    #[inline]
    fn is_empty(&self) -> bool {
        self.hop_by_hop.is_none()
            && self.routing.is_none()
            && self.fragment.is_none()
            && self.auth_header.is_none()
            && self.destination_1st.is_none()
            && self.destination_2nd.is_none()
    }
}
