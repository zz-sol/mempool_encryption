use hkdf::Hkdf;
use sha2::Sha256;

use crate::types::Error;

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
}

pub fn hkdf_expand(prk: &Hkdf<Sha256>, info: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    let mut okm = vec![0u8; out_len];
    prk.expand(info, &mut okm).map_err(|_| Error::CryptoError)?;
    Ok(okm)
}
