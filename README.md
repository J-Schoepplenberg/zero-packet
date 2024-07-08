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

If you want to create network packets manually and efficiently, look no further.

```Rust
// Raw packet that we will mutate in-place.
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

// PacketParser is a zero-copy packet parser.
// The new method is very lenient and accepts any slice.
// Does not check any fields.
let lax_parsing = PacketParser::new(&packet);

// The parse method determines on its own what protocol headers are present.
// The method is strict about what input it accepts and validates certain fields.
let strict_parsing = PacketParser::parse(&packet)?;

// Now it is as easy as this.
if let Some(ethernet) = strict_parsing.ethernet {
    let ethertype = ethernet.get_ethertype();
    // ...
}

// Or this.
if let Some(ipv4) = strict_parsing.ipv4 {
    let src_ip = ipv4.get_src_ip();
    // ...
}
```

## Roadmap

Upcoming features:
- [ ] IPv6
- [ ] ICMPv6
- [ ] IPsec