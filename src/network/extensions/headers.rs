use super::routing::RoutingHeaderReader;
use crate::misc::NextHeader;

/// Contains all present extension headers in an IPv6 packet.
/// 
/// Each extension header is optional and can appear only once.
/// 
/// Except the Destination Options header, which can occur twice.
#[derive(Debug)]
pub struct ExtensionHeaders<'a> {
    pub routing: Option<RoutingHeaderReader<'a>>,
}

impl<'a> ExtensionHeaders<'a> {
    /// Parses the extension headers from the given byte slice.
    /// 
    /// They are chained together through the next header field.
    /// 
    /// Thus, we need to loop through them all to run down the chain.
    #[inline]
    pub fn new(bytes: &'a [u8], next_header: u8) -> Result<Option<Self>, &'static str> {
        let mut routing = None;
        let mut next_header = next_header;

        loop {
            match NextHeader::from(next_header) {
                NextHeader::Routing => {
                    let reader = RoutingHeaderReader::new(bytes)?;
                    next_header = reader.next_header();
                    routing = Some(reader);
                }
                // We escape the loop if we don't recognize the next header.
                _ => break,
            }
        }

        Ok(Some(Self { routing }))
    }

    /// Returns the total length of all present extension headers.
    #[inline]
    pub fn total_header_len(&self) -> usize {
        let mut total_len = 0;

        if let Some(routing) = &self.routing {
            total_len += routing.header_len();
        }

        total_len
    }
}
