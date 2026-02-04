use crate::types::Error;

pub fn enc_len(len: usize) -> [u8; 4] {
    if len > u32::MAX as usize {
        // Truncate with best effort; caller should avoid.
        return (u32::MAX).to_be_bytes();
    }
    (len as u32).to_be_bytes()
}

pub fn enc_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&enc_len(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

pub fn enc_tuple(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        out.extend_from_slice(&enc_len(part.len()));
        out.extend_from_slice(part);
    }
    out
}

pub fn dec_bytes(input: &[u8]) -> Result<(Vec<u8>, &[u8]), Error> {
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
