//! Common types and error handling.

use serde::{Deserialize, Serialize};

pub type PartyId = u32;

pub trait Wire: Sized {
    // Canonical byte encoding for network transport.
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Params {
    pub n: u32,
    pub t: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PartyInfo {
    pub id: PartyId,
}

#[derive(Debug)]
pub enum Error {
    InvalidParams,
    InvalidEncoding,
    InvalidMessage,
    InvalidShare,
    InvalidSignature,
    InvalidWitness,
    CryptoError,
    DecryptionFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

pub fn validate_params(params: Params) -> Result<(), Error> {
    // Basic sanity: non-zero, and threshold not exceeding committee size.
    if params.n == 0 || params.t == 0 || params.t > params.n {
        return Err(Error::InvalidParams);
    }
    Ok(())
}

impl From<hkdf::InvalidLength> for Error {
    fn from(_: hkdf::InvalidLength) -> Self {
        Error::CryptoError
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Error::CryptoError
    }
}
