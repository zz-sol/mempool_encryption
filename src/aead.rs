//! AEAD helpers (AES-128-GCM).

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};

use crate::types::Error;

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 16;

pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    // AEAD encrypt with AES-128-GCM.
    if key.len() != KEY_LEN || nonce.len() != NONCE_LEN {
        return Err(Error::InvalidParams);
    }
    let key = GenericArray::from_slice(key);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::CryptoError)
}

pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    // AEAD decrypt; returns DecryptionFailed on authentication error.
    if key.len() != KEY_LEN || nonce.len() != NONCE_LEN {
        return Err(Error::InvalidParams);
    }
    let key = GenericArray::from_slice(key);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::DecryptionFailed)
}
