#![forbid(unsafe_code)]

//! Mempool encryption: DKG + threshold BLS signatures + KEM (BLS12-381 / blstrs).
//! This crate provides scheme traits plus a concrete BLS implementation.

pub mod aead;
pub mod bls;
pub mod dkg;
pub mod encoding;
pub mod kdf;
pub mod kem;
pub mod lagrange;
pub mod logging;
pub mod scheme;
pub mod transport;
pub mod types;
mod wire_impls;

pub use crate::scheme::{MempoolEncryptionScheme, SetupProtocol, ThresholdRelease};
pub use crate::types::{Error, Params, PartyId, PartyInfo, Wire};
