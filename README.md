# Spark Address

A minimal, **no-std**-compatible Rust library for encoding and decoding _Spark_ Bech32m addresses.

- 100 % safe Rust
- Works in `no_std` + `alloc` environments
- Optional secp256k1 public-key validation

---

## Quick start

Add the crate to your `Cargo.toml`:

```toml
spark-address = "0.1"
```

Enable optional features if you need them:

```toml
spark-address = { version = "0.1", default-features = false, features = ["validate-secp256k1"] }
```

---

### Example

```rust
use spark_address::{
    encode_spark_address, decode_spark_address, SparkAddressData, Network,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compressed 33-byte secp256k1 public key (hex encoded)
    let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    // Build the data structure we want to encode
    let data = SparkAddressData {
        identity_public_key: pubkey.into(),
        network: Network::Mainnet,
    };

    // Encode → `sp1…`
    let addr = encode_spark_address(&data)?;
    println!("Spark address: {addr}");

    // Decode back
    let decoded = decode_spark_address(&addr)?;
    assert_eq!(decoded, data);
    Ok(())
}
```

---

## Features

| Feature              | Default | Description                                                                                               |
| -------------------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `std`                | ✓       | Use the Rust standard library. Disable it for `#![no_std]` targets.                                       |
| `validate-secp256k1` |         | Verify that the supplied public key is a valid compressed **secp256k1** key (uses the `secp256k1` crate). |

The crate has **no transitive dependencies** beyond `bech32` and `hex` (plus `secp256k1` when validation is enabled).

---

## Address format

A Spark address is a standard Bech32m string consisting of:

1. A human-readable part (HRP) identifying the network: `sp`, `spt`, `sps`, `sprt`, or `spl`.
2. A tiny protobuf-like payload containing a single field (tag `0x0a`) that wraps a **33-byte compressed secp256k1 public key**.

For full details see the implementation in [`src/lib.rs`](src/lib.rs).

---

## License

Licensed under either of

- Apache License, Version 2.0, or
- MIT license

at your option.
