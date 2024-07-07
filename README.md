# zero-packet

Super simple, highly efficient Rust library that builds and parses network packets in-place with zero overhead.

No async, no allocations, no dependencies, no macros, no std, no unsafe. It simply cannot be easier.

Supported protocols:
- Ethernet
- ARP
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- ICMPv6

Use `zero-packet` if you are working with raw sockets.