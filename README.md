# zero-packet

Super simple library to efficiently build and parse network packets in-place with zero overhead.

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

## Getting started

Install via your command line:

```bash
cargo add zero-packet
```

Or add the following to your `Cargo.toml`:

```toml
[dependencies]
zero-packet = "0.0.1"
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
// The `parse` method determines on its own what protocol headers are present.
// The method is strict about what input it accepts and validates certain fields.
let parsed = PacketParser::parse(&packet)?;

// Now it is as easy as this.
if let Some(ethernet) = parsed.ethernet {
    let ethertype = ethernet.get_ethertype();
    // ...
}

// Or this.
if let Some(ipv4) = parsed.ipv4 {
    let src_ip = ipv4.get_src_ip();
    // ...
}

// Alternatively, just parse headers directly manually.
// By adjusting the index of the slice you can find different headers.
if let Some(tcp) = TcpParser::new(&packet)? {
    let src_port = tcp.get_src_port();
    // ...
}

```

## Roadmap

Upcoming features:
- [ ] IPv6
- [ ] ICMPv6
- [ ] IPsec
- [ ] ...