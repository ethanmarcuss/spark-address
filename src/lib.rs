//! Minimal Spark address codec.
//! Avoids unsafe code and works in `no_std` + `alloc` environments.
//!
//! # Crate Overview
//! The **spark-address** crate encodes & decodes *Spark* Bech32m addresses. A Spark
//! address couples a compressed secp256k1 public key with a network identifier
//! (see [`Network`]) and represents them as human-friendly Bech32m strings like
//! `spark1…` or `sparkrt1…`.
//!
//! ```rust
//! use spark_address::{encode_spark_address, decode_spark_address, SparkAddressData, Network};
//!
//! let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
//! let data = SparkAddressData { identity_public_key: pubkey.into(), network: Network::Mainnet };
//! let addr = encode_spark_address(&data)?;
//! let decoded = decode_spark_address(&addr)?;
//! assert_eq!(decoded, data);
//! # Ok::<(), spark_address::SparkAddressError>(())
//! ```
//!
//! ## Feature Flags
//! * **`std`** *(default)* — Use the Rust standard library. Disable to build for
//!   `#![no_std]` + `alloc` targets.
//! * **`validate-secp256k1`** — Validate the public key using the `secp256k1` crate.
//!
//! ## MSRV
//! Minimum supported Rust version: **1.70**.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::string::ToString;
use bech32::{self, Bech32m, Hrp};
use core::fmt;
use hex::{decode as hex_to_bytes, encode as bytes_to_hex};

// `Vec` / `String` come from `alloc` when `std` is disabled.
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

/* ------------------------------------------------------------- *
 *  Network ⇄ HRP                                                 *
 * ------------------------------------------------------------- */

/// Networks supported by Spark.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Network {
    /// Main Bitcoin network (`spark` prefix).
    Mainnet,
    /// Bitcoin testnet (`sparkt` prefix).
    Testnet,
    /// Signet (`sparks` prefix).
    Signet,
    /// Regression-test network (`sparkrt` prefix).
    Regtest,
    /// Local development network (`sparkl` prefix).
    Local,
}

impl Network {
    fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "spark",
            Network::Testnet => "sparkt",
            Network::Signet => "sparks",
            Network::Regtest => "sparkrt",
            Network::Local => "sparkl",
        }
    }

    fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            "spark" => Some(Network::Mainnet),
            "sparkt" => Some(Network::Testnet),
            "sparks" => Some(Network::Signet),
            "sparkrt" => Some(Network::Regtest),
            "sparkl" => Some(Network::Local),
            _ => None,
        }
    }
}

/* ------------------------------------------------------------- *
 *  Error type                                                    *
 * ------------------------------------------------------------- */

#[derive(Debug)]
pub enum SparkAddressError {
    /// The Bech32 string failed to decode.
    InvalidBech32(bech32::DecodeError),
    /// The human-readable part (HRP) does not correspond to a known [`Network`].
    UnknownPrefix(String),
    /// The checksum was valid **Bech32** but not **Bech32m**.
    InvalidVariant,
    /// The string mixes upper- and lower-case characters.
    MixedCase,
    /// The address exceeded the 90-character limit specified by BIP-350.
    InvalidLength,
    /// The embedded pseudo-protobuf payload was malformed.
    BadProto,
    /// Public key hex failed to decode.
    Hex(hex::FromHexError),
    /// Public key length differed from 33 bytes.
    WrongKeyLength(usize),
    #[cfg(feature = "validate-secp256k1")]
    /// The provided public key is not a valid compressed secp256k1 key.
    InvalidSecp256k1,
    /// Failure while encoding back into Bech32m.
    Bech32Encode(bech32::EncodeError),
}

impl fmt::Display for SparkAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SparkAddressError::InvalidBech32(e) => write!(f, "bech32 decode error: {e}"),
            SparkAddressError::UnknownPrefix(p) => write!(f, "unknown HRP prefix: {p}"),
            SparkAddressError::InvalidVariant => write!(f, "bech32 variant is not Bech32m"),
            SparkAddressError::MixedCase => write!(f, "address contains mixed upper/lower case"),
            SparkAddressError::InvalidLength => write!(f, "address exceeds maximum length (90)"),
            SparkAddressError::BadProto => write!(f, "invalid proto payload"),
            SparkAddressError::Hex(e) => write!(f, "hex decode error: {e}"),
            SparkAddressError::WrongKeyLength(n) => {
                write!(f, "wrong pubkey length: {n} (expected 33)")
            }
            #[cfg(feature = "validate-secp256k1")]
            SparkAddressError::InvalidSecp256k1 => write!(f, "invalid secp256k1 pubkey"),
            SparkAddressError::Bech32Encode(e) => write!(f, "bech32 encode error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SparkAddressError {}

impl From<bech32::DecodeError> for SparkAddressError {
    fn from(e: bech32::DecodeError) -> Self {
        Self::InvalidBech32(e)
    }
}

impl From<bech32::EncodeError> for SparkAddressError {
    fn from(e: bech32::EncodeError) -> Self {
        Self::Bech32Encode(e)
    }
}

impl From<hex::FromHexError> for SparkAddressError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

/* ------------------------------------------------------------- *
 *  SparkAddressData                                              *
 * ------------------------------------------------------------- */

/// Result of a successful decode, or input to `encode`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SparkAddressData {
    /// Compressed secp256k1 public key, hex-encoded (`02/03 + 32 bytes`).
    pub identity_public_key: String,
    /// Network for which the address is intended (determines HRP prefix).
    pub network: Network,
}

/* ------------------------------------------------------------- *
 *  Tiny "proto" wrapper (field-1, wire-type 2)                   *
 * ------------------------------------------------------------- */

const TAG: u8 = 0x0a; // (1 << 3) | 2

fn encode_proto(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + key.len());
    out.push(TAG);
    // Compressed pubkeys are 33 bytes; fall back to error if ever larger.
    let key_len: u8 = key.len().try_into().expect("key length exceeds 255 bytes");
    out.push(key_len);
    out.extend_from_slice(key);
    out
}

fn decode_proto(buf: &[u8]) -> Result<&[u8], SparkAddressError> {
    if buf.len() >= 3 && buf[0] == TAG && buf[1] as usize + 2 == buf.len() {
        Ok(&buf[2..])
    } else {
        Err(SparkAddressError::BadProto)
    }
}

/* ------------------------------------------------------------- *
 *  Public API                                                    *
 * ------------------------------------------------------------- */

/// Encode a `(pubkey, network)` into a Spark Bech32m address.
///
/// # Panics
///
/// This function will panic if the HRP (Human Readable Part) is invalid. This should never happen
/// in practice as the HRP is statically defined in the `Network` enum.
///
/// # Errors
///
/// This function will return an error if:
/// * The public key is invalid hex (`SparkAddressError::Hex`)
/// * The public key length is not 33 bytes (`SparkAddressError::WrongKeyLength`)
/// * The public key is invalid secp256k1 (when `validate-secp256k1` feature is enabled) (`SparkAddressError::InvalidSecp256k1`)
/// * The bech32 encoding fails (`SparkAddressError::Bech32Encode`)
pub fn encode_spark_address(data: &SparkAddressData) -> Result<String, SparkAddressError> {
    #[cfg(feature = "validate-secp256k1")]
    validate_pubkey(&data.identity_public_key)?;

    let key_bytes = hex_to_bytes(&data.identity_public_key)?;
    if key_bytes.len() != 33 {
        return Err(SparkAddressError::WrongKeyLength(key_bytes.len()));
    }

    let proto = encode_proto(&key_bytes);

    let hrp = Hrp::parse(data.network.hrp()).expect("static HRP is valid");
    let addr = bech32::encode::<Bech32m>(hrp, &proto)?;

    Ok(addr)
}

/// Decode a Spark address, returning `(pubkey, network)`.
///
/// # Errors
///
/// This function will return an error if:
/// * The address is not valid bech32m (`SparkAddressError::InvalidBech32`)
/// * The address has an unknown prefix (`SparkAddressError::UnknownPrefix`)
/// * The address has invalid protocol data (`SparkAddressError::BadProto`)
/// * The public key length is not 33 bytes (`SparkAddressError::WrongKeyLength`)
/// * The public key is invalid secp256k1 (when `validate-secp256k1` feature is enabled) (`SparkAddressError::InvalidSecp256k1`)
pub fn decode_spark_address(addr: &str) -> Result<SparkAddressData, SparkAddressError> {
    // -----------------------------------------------------------------
    // Early sanity checks (avoid allocating in `bech32::decode` when we
    // already know the string is invalid).
    // -----------------------------------------------------------------
    if addr.len() > 90 {
        return Err(SparkAddressError::InvalidLength);
    }

    let has_upper = addr.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = addr.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return Err(SparkAddressError::MixedCase);
    }

    let (hrp, proto) = bech32::decode(addr)?;

    // The Bech32 spec requires the HRP to be lowercase. The `bech32`
    // crate accepts uppercase HRPs, so we enforce the stricter rule
    // here.
    let hrp_str = hrp.to_string();
    if hrp_str.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(SparkAddressError::MixedCase);
    }

    // Reject legacy Bech32 (BIP-173) by re-encoding with Bech32m and
    // comparing the checksum. If it differs, the original variant must
    // have been classic Bech32.
    let reencoded = bech32::encode::<Bech32m>(hrp, &proto)?;
    if reencoded.to_lowercase() != addr.to_lowercase() {
        return Err(SparkAddressError::InvalidVariant);
    }

    let network = Network::from_hrp(&hrp_str)
        .ok_or_else(|| SparkAddressError::UnknownPrefix(hrp_str.clone()))?;

    let key = decode_proto(&proto)?;

    if key.len() != 33 {
        return Err(SparkAddressError::WrongKeyLength(key.len()));
    }

    let hex_key = bytes_to_hex(key);

    #[cfg(feature = "validate-secp256k1")]
    validate_pubkey(&hex_key)?;

    Ok(SparkAddressData {
        identity_public_key: hex_key,
        network,
    })
}

/* ------------------------------------------------------------- *
 *  (feature-gated) secp256k1 validation                               *
 * ------------------------------------------------------------- */

#[cfg(feature = "validate-secp256k1")]
fn validate_pubkey(hex_str: &str) -> Result<(), SparkAddressError> {
    use secp256k1::PublicKey;
    let bytes = hex_to_bytes(hex_str)?;
    PublicKey::from_slice(&bytes).map_err(|_| SparkAddressError::InvalidSecp256k1)?;
    Ok(())
}

#[cfg(not(feature = "validate-secp256k1"))]
fn _validate_pubkey(_: &str) {}

/* ------------------------------------------------------------- *
 *  Tests                                                         *
 * ------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    const PUBKEY: &str = "02894808873b896e21d29856a6d7bb346fb13c019739adb9bf0b6a8b7e28da53da";
    const MAINNET_ADDRESS: &str =
        "spark1pgss9z2gpzrnhztwy8ffs44x67angma38sqewwddhxlsk65t0c5d5576quly2j";

    #[test]
    fn mainnet_round_trip() {
        let data = SparkAddressData {
            identity_public_key: PUBKEY.into(),
            network: Network::Mainnet,
        };
        let encoded = encode_spark_address(&data).unwrap();
        assert_eq!(encoded, MAINNET_ADDRESS);
        let decoded = decode_spark_address(&encoded).unwrap();
        assert_eq!(decoded, data);

        let decoded = decode_spark_address(MAINNET_ADDRESS).unwrap();
        assert_eq!(decoded.network, Network::Mainnet);
        assert_eq!(decoded.identity_public_key, PUBKEY);
    }
}
