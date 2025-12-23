use proptest::prelude::*;
use spark_address::{decode_spark_address, encode_spark_address, Network, SparkAddressData};

#[cfg(not(feature = "validate-secp256k1"))]
proptest! {
    #[test]
    fn round_trip_random_key(bytes in proptest::array::uniform32(any::<u8>())) {
        // Choose prefix 0x02 or 0x03 randomly (compressed pubkey y-parity bit).
        let leading = if bytes[0] & 1 == 0 { 0x02u8 } else { 0x03u8 };
        let mut full = Vec::with_capacity(33);
        full.push(leading);
        full.extend_from_slice(&bytes);

        let hex_key = hex::encode(&full);
        let original = SparkAddressData { identity_public_key: hex_key.clone(), network: Network::Signet };
        let addr = encode_spark_address(&original).expect("encode");
        let decoded = decode_spark_address(&addr).expect("decode");
        prop_assert_eq!(decoded, original);
    }
}

#[cfg(feature = "validate-secp256k1")]
proptest! {
    use secp256k1::Secp256k1;
    #[test]
    fn round_trip_valid_secp_key(_ in 0..10u8) { // generate 10 cases per proptest iteration
        let secp = Secp256k1::new();
        for _ in 0..10 {
            let (_sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
            let hex_key = hex::encode(pk.serialize());
            let original = SparkAddressData { identity_public_key: hex_key.clone(), network: Network::Testnet };
            let addr = encode_spark_address(&original).unwrap();
            let decoded = decode_spark_address(&addr).unwrap();
            prop_assert_eq!(decoded, original);
        }
    }
}
