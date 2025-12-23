use bech32::{self, Bech32m, Hrp};
use hex::decode as hex_to_bytes;
use spark_address::{
    decode_spark_address, encode_spark_address, Network, SparkAddressData, SparkAddressError,
};

const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TAG: u8 = 0x0a;

#[test]
fn unknown_prefix() {
    // Build a valid address but with an unknown HRP ("xx").
    let key_bytes = hex_to_bytes(PUBKEY).unwrap();
    let mut proto = Vec::with_capacity(2 + key_bytes.len());
    proto.push(TAG);
    proto.push(key_bytes.len() as u8);
    proto.extend_from_slice(&key_bytes);

    let hrp = Hrp::parse("xx").unwrap();
    let addr = bech32::encode::<Bech32m>(hrp, &proto).unwrap();

    match decode_spark_address(&addr) {
        Err(SparkAddressError::UnknownPrefix(_)) => {}
        other => panic!("expected UnknownPrefix, got {:?}", other),
    }
}

#[test]
fn bad_proto_tag() {
    // Start from a valid mainnet address, then flip the proto tag byte.
    let data = SparkAddressData {
        identity_public_key: PUBKEY.into(),
        network: Network::Mainnet,
    };
    let good_addr = encode_spark_address(&data).unwrap();

    // Decode to get the payload, mutate, re-encode.
    let (hrp, mut proto) = bech32::decode(&good_addr).unwrap();
    // Flip first byte (tag) so it no longer matches 0x0a.
    proto[0] ^= 0x01;
    let broken_addr = bech32::encode::<Bech32m>(hrp, &proto).unwrap();

    match decode_spark_address(&broken_addr) {
        Err(SparkAddressError::BadProto) => {}
        other => panic!("expected BadProto, got {:?}", other),
    }
}

#[test]
fn wrong_key_length_encode() {
    // 32-byte (64-hex-char) key instead of 33-byte.
    let short_key = "03".to_string() + &"00".repeat(31); // 64 chars total
    let data = SparkAddressData {
        identity_public_key: short_key,
        network: Network::Mainnet,
    };
    match encode_spark_address(&data) {
        Err(SparkAddressError::WrongKeyLength(32)) => {}
        other => panic!("expected WrongKeyLength(32), got {:?}", other),
    }
}

#[test]
fn wrong_key_length_decode() {
    // Craft proto with only 32 bytes of key material.
    let key_bytes = vec![0u8; 32];
    let mut proto = Vec::with_capacity(2 + key_bytes.len());
    proto.push(TAG);
    proto.push(key_bytes.len() as u8);
    proto.extend_from_slice(&key_bytes);

    let hrp = Hrp::parse("spark").unwrap();
    let addr = bech32::encode::<Bech32m>(hrp, &proto).unwrap();

    match decode_spark_address(&addr) {
        Err(SparkAddressError::WrongKeyLength(32)) => {}
        other => panic!("expected WrongKeyLength(32), got {:?}", other),
    }
}

#[test]
fn mixed_case_address() {
    // Upper-case first letter of a valid address -> mixed-case error.
    let data = SparkAddressData {
        identity_public_key: PUBKEY.into(),
        network: Network::Mainnet,
    };
    let good_addr = encode_spark_address(&data).unwrap();
    let mut chars: Vec<char> = good_addr.chars().collect();
    chars[0] = chars[0].to_ascii_uppercase();
    let bad_addr: String = chars.into_iter().collect();

    match decode_spark_address(&bad_addr) {
        Err(SparkAddressError::MixedCase) => {}
        other => panic!("expected MixedCase, got {:?}", other),
    }
}

#[test]
fn checksum_error() {
    // Flip the last character of a valid address (will break checksum)
    let data = SparkAddressData {
        identity_public_key: PUBKEY.into(),
        network: Network::Mainnet,
    };
    let mut addr = encode_spark_address(&data).unwrap();
    // Last char is within charset, replace with a different valid char.
    let last = addr.pop().unwrap();
    let replacement = if last != 'q' { 'q' } else { 'p' }; // simple change
    addr.push(replacement);

    match decode_spark_address(&addr) {
        Err(SparkAddressError::InvalidBech32(_)) => {}
        other => panic!("expected InvalidBech32, got {:?}", other),
    }
}
