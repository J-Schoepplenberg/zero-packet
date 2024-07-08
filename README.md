# zero-packet

Super simple, highly efficient Rust library that builds and parses network packets in-place with zero overhead.

No async, no allocations, no dependencies, no macros, no std, no unsafe. It simply cannot be easier.

Use `zero-packet` if you are working with raw sockets.

Supported protocols:
- Ethernet
- ARP
- IPv4
- TCP
- UDP
- ICMP

## Usage

### Install

```bash
cargo add zero-packet
```

### PacketBuilder

If you want to create network packets manually, look no further.

```Rust
// Raw packet that we will mutate.
// Ethernet header (14 bytes) + IPv4 header (20 bytes) + UDP header (8 bytes) = 42 bytes.
let mut packet = [0u8; 53]

// Some random payload (11 bytes).
let payload = b"Hello, UDP!";

// PacketBuilder which holds a mutable reference to the byte slice.
let mut packet_builder = PacketBuilder::new(&mut packet);

// Sets Ethernet, IPv4 and UDP header fields.
// Optional: add payload to the packet.
// Encapsulates everything in the given byte slice.
packet_builder
    .ethernet(src_mac, dest_mac, ethertype)?
    .ipv4(version, ihl, dscp, ecn, total_length, id, flags, fragment_offset, ttl, protocol, src_ip, dest_ip)?
    .udp(src_ip, src_port, dest_ip, dest_port, length)?
    .payload(payload)?;
```

### PacketParser

Parsing any received byte slice for which we don't know ahead of time what type of packet it is.

```Rust
// Some byte slice that we have received.
// We don't know yet what it contains.
let packet = [..];

// PacketParser which holds a reference to the byte slice.
// Determines what protocol headers are present.
let packet_parser = PacketParser::parse(&packet)?;
```