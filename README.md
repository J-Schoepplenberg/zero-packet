# zero-packet

[![crates.io](https://img.shields.io/crates/v/zero-packet.svg)](https://crates.io/crates/zero-packet)
[![MIT](https://img.shields.io/badge/License-MIT-orange.svg)](https://github.com/J-Schoepplenberg/zero-packet/blob/main/LICENSE)
[![docs.rs](https://docs.rs/zero-packet/badge.svg)](https://docs.rs/zero-packet/latest/zero_packet/index.html)

Super simple library to efficiently build and parse network packets in-place with zero overhead.

No async, no allocations, no dependencies, no std, no unsafe. It simply cannot be easier.

Use `zero-packet` if you are working with raw sockets, low-level networking, or something similar.

## Supported

You can build and parse a wide variety of packets of arbitrary complexity.

- Ethernet II
    - Optional
        - VLAN tagging
        - Double tagging
- ARP
- IPv4
- IPv6
    - Extension headers
        - Hop-by-Hop Options
        - Routing
        - Fragment
        - Authentication Header
        - Destination Options (1st and 2nd)
- IP-in-IP
    - Encapsulation
        - IPv4 in IPv4
        - IPv4 in IPv6
        - IPv6 in IPv4
        - IPv6 in IPv6
- ICMPv4
- ICMPv6
- TCP
- UDP

## Usage

### Getting started

Install via your command line:

```bash
cargo add zero-packet
```

Or add the following to your `Cargo.toml`:

```toml
[dependencies]
zero-packet = "0.1.0"
```

### PacketBuilder

If you want to create network packets manually and efficiently, look no further.

```Rust
// Raw packet that we will mutate in-place.
// Ethernet header (14 bytes) + IPv4 header (20 bytes) + UDP header (8 bytes) = 42 bytes.
let mut buffer = [0u8; 64]

// Some random payload (11 bytes).
let payload = b"Hello, UDP!";

// PacketBuilder is a zero-copy packet builder.
// Using the typestate pattern, a state machine is implemented at compile-time.
// The state machine ensures that the package is built structurally correct.
let mut packet_builder = PacketBuilder::new(&mut buffer);

// Sets Ethernet, IPv4 and UDP header fields.
// Optional: add payload to the packet.
// Encapsulates everything in the given byte slice.
let packet: &[u8] = packet_builder
    .ethernet(src_mac, dest_mac, ethertype)?
    .ipv4(version, ihl, dscp, ecn, total_length, id, flags, fragment_offset, ttl, protocol, src_ip, dest_ip)?
    .udp(src_ip, src_port, dest_ip, dest_port, length, Some(payload))?
    .build();
```

### PacketParser

Parsing any received byte slice for which we don't know ahead of time what type of packet it is.

```Rust
// Some byte slice that we have received.
// We don't know yet what it contains.
let packet = [..];

// PacketParser is a zero-copy packet parser.
// The `parse` method recognizes which protocol headers are present.
let parsed = PacketParser::parse(&packet)?;

// Now it is as easy as this.
if let Some(ethernet) = parsed.ethernet {
    let ethertype = ethernet.ethertype();
    // ...
}

// Or this.
if let Some(ipv4) = parsed.ipv4 {
    let src_ip = ipv4.src_ip();
    // ...
}

// Alternatively, just manually read headers directly.
// By adjusting the index of the slice you can find different headers.
if let Some(tcp) = TcpReader::new(&packet)? {
    let src_port = tcp.src_port();
    // ...
}

```