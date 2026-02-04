use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::types::Error;

pub const NONCE_LEN: usize = 12;

pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 || nonce.len() != NONCE_LEN {
        return Err(Error::InvalidParams);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
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
    if key.len() != 32 || nonce.len() != NONCE_LEN {
        return Err(Error::InvalidParams);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
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
