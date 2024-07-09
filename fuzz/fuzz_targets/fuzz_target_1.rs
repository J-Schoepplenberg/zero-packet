#![no_main]

use libfuzzer_sys::fuzz_target;
use zero_packet::packet::parser::PacketParser;

fuzz_target!(|data: &[u8]| {
    let parsed = PacketParser::parse(&data);
});
