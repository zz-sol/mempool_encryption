//! Length-prefixed encoding helpers for wire formats.

use crate::types::Error;

pub fn enc_len(len: usize) -> Result<[u8; 4], Error> {
    // Lengths are encoded as 4-byte big-endian.
    if len > u32::MAX as usize {
        return Err(Error::InvalidEncoding);
    }
    Ok((len as u32).to_be_bytes())
}

pub fn enc_bytes(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    // Length-prefix encoding: [len||bytes].
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&enc_len(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(out)
}

pub fn enc_tuple(parts: &[&[u8]]) -> Result<Vec<u8>, Error> {
    // Concatenate length-prefixed parts in order.
    let total_len: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        out.extend_from_slice(&enc_len(part.len())?);
        out.extend_from_slice(part);
    }
    Ok(out)
}

pub fn dec_bytes(input: &[u8]) -> Result<(Vec<u8>, &[u8]), Error> {
    // Decode a single length-prefixed byte string.
    if input.len() < 4 {
        return Err(Error::InvalidEncoding);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&input[0..4]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    if input.len() < 4 + len {
        return Err(Error::InvalidEncoding);
    }
    let data = input[4..4 + len].to_vec();
    Ok((data, &input[4 + len..]))
}
