/// Convert a byte slice to a hex string
/// 
/// Used when debug printing mac addresses to the console.
pub fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
}
